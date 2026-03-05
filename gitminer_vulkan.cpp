#include <vulkan/vulkan.h>
#include <cstdio>
#include <cstdint>
#include <cinttypes>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include <vector>

using namespace std;

#define range_lower 'a'
#define range_upper 'z'

int g_nonce_start = 237;
int g_nonce_end = 246;
int g_target_zeros = 0;
int logmode = 1;
string filename_log, filename_out;

string g_target_prefix_str;
uint32_t g_prefix[5] = {0};
uint32_t g_prefix_mask[5] = {0};
int g_prefix_mode = 0;

void parse_hex_prefix(const char *hex, uint32_t *prefix, uint32_t *mask) {
	memset(prefix, 0, 5 * sizeof(uint32_t));
	memset(mask, 0, 5 * sizeof(uint32_t));
	int len = strlen(hex);
	for (int i = 0; i < len && i < 40; i++) {
		int word = i / 8;
		int shift = (7 - (i % 8)) * 4;
		char c = hex[i];
		uint8_t val;
		if (c >= '0' && c <= '9') val = c - '0';
		else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
		else { fprintf(stderr, "Invalid hex character: %c\n", c); exit(1); }
		prefix[word] |= (uint32_t)val << shift;
		mask[word] |= (uint32_t)0xF << shift;
	}
}

// ── Host-side SHA-1 (for pre-compute cache) ──────────────────────────

#define rol(x, n) (((x)<<(n))|((x)>>(32-(n))))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define blk0(i) (w[i] = (rol(w[i],24)&0xff00ff00)|(rol(w[i],8)&0x00ff00ff))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define blk0(i) w[i]
#endif

#define blk(i) (w[i&0xf]=rol(w[(i+13)&0xf]^w[(i+8)&0xf]^w[(i+2)&0xf]^w[i&0xf],1))
#define R0(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk0(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R1(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R2(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0x6ed9eba1+rol(l,5);m=rol(m,30);
#define R3(l,m,n,o,p,q) p+=(((m|n)&o)|(m&n))+blk(q)+0x8f1bbcdc+rol(l,5);m=rol(m,30);
#define R4(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0xca62c1d6+rol(l,5);m=rol(m,30);

inline void sha1_expand(uint8_t *data, int *data_len) {
	uint64_t m1 = (uint64_t)(*data_len) * 8;
	data[*data_len] = 0x80;
	uint32_t seq = (*data_len) + 1;
	*data_len = ((*data_len) + 8) / 64 * 64 + 56;
	memset(data + seq, 0x00, (*data_len) - seq);
	data[(*data_len)] = (m1 >> 56) & 0xff; data[++(*data_len)] = (m1 >> 48) & 0xff;
	data[++(*data_len)] = (m1 >> 40) & 0xff; data[++(*data_len)] = (m1 >> 32) & 0xff;
	data[++(*data_len)] = (m1 >> 24) & 0xff; data[++(*data_len)] = (m1 >> 16) & 0xff;
	data[++(*data_len)] = (m1 >> 8) & 0xff; data[++(*data_len)] = (m1) & 0xff;
	++(*data_len);
}

inline void sha1_block(uint8_t *data_block, uint32_t *result) {
	uint32_t a, b, c, d, e;
	uint32_t w[16];
	memcpy(w, (uint32_t*)data_block, 64);
	a = result[0]; b = result[1]; c = result[2]; d = result[3]; e = result[4];
	R0(a,b,c,d,e,0); R0(e,a,b,c,d,1); R0(d,e,a,b,c,2); R0(c,d,e,a,b,3);
	R0(b,c,d,e,a,4); R0(a,b,c,d,e,5); R0(e,a,b,c,d,6); R0(d,e,a,b,c,7);
	R0(c,d,e,a,b,8); R0(b,c,d,e,a,9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	result[0] += a; result[1] += b; result[2] += c; result[3] += d; result[4] += e;
}

inline void sha1_init(uint32_t *result) {
	result[0] = 0x67452301; result[1] = 0xefcdab89;
	result[2] = 0x98badcfe; result[3] = 0x10325476; result[4] = 0xc3d2e1f0;
}

// ── Utility functions ────────────────────────────────────────────────

inline bool has_leading_zeros(const uint32_t *result, int target) {
	int full_words = target / 8;
	int remaining = target % 8;
	for (int i = 0; i < full_words && i < 5; ++i)
		if (result[i] != 0) return false;
	if (remaining > 0 && full_words < 5) {
		uint32_t mask = ~((1u << (32 - remaining * 4)) - 1);
		if (result[full_words] & mask) return false;
	}
	return true;
}

inline bool is_lower_hash(const uint32_t *a, const uint32_t *b) {
	for (int i = 0; i < 5; ++i) {
		if (a[i] < b[i]) return true;
		if (a[i] > b[i]) return false;
	}
	return false;
}

void init_nonce(uint8_t *nonce, int nonce_size) {
	int nonce_len_var = min(6, nonce_size);
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<int> dist(range_lower, range_upper);
	for (int i = nonce_len_var; i < nonce_size; ++i)
		nonce[i] = (uint8_t)dist(mt);
	for (int i = 0; i < nonce_len_var; ++i)
		nonce[i] = (uint8_t)range_lower;
}

void log_msg(string output) {
	ofstream file_log;
	file_log.open(filename_log, ios::out | ios::app);
	file_log << output << endl;
	if (logmode) cout << output << endl;
	file_log.close();
}

// ── Vulkan helpers ───────────────────────────────────────────────────

#define VK_CHECK(call) do { \
	VkResult res = call; \
	if (res != VK_SUCCESS) { \
		fprintf(stderr, "Vulkan error at %s:%d: %d\n", __FILE__, __LINE__, (int)res); \
		exit(1); \
	} \
} while(0)

static uint32_t findMemoryType(VkPhysicalDevice physDevice, uint32_t typeFilter, VkMemoryPropertyFlags properties) {
	VkPhysicalDeviceMemoryProperties memProps;
	vkGetPhysicalDeviceMemoryProperties(physDevice, &memProps);
	for (uint32_t i = 0; i < memProps.memoryTypeCount; i++) {
		if ((typeFilter & (1 << i)) && (memProps.memoryTypes[i].propertyFlags & properties) == properties)
			return i;
	}
	fprintf(stderr, "Failed to find suitable memory type\n");
	exit(1);
}

struct VulkanBuffer {
	VkBuffer buffer;
	VkDeviceMemory memory;
	VkDeviceSize size;
	void *mapped;
};

static VulkanBuffer createBuffer(VkDevice device, VkPhysicalDevice physDevice, VkDeviceSize size, VkBufferUsageFlags usage, VkMemoryPropertyFlags memProps) {
	VulkanBuffer buf = {};
	buf.size = size;
	buf.mapped = nullptr;

	VkBufferCreateInfo bufInfo = {};
	bufInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
	bufInfo.size = size;
	bufInfo.usage = usage;
	bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
	VK_CHECK(vkCreateBuffer(device, &bufInfo, nullptr, &buf.buffer));

	VkMemoryRequirements memReqs;
	vkGetBufferMemoryRequirements(device, buf.buffer, &memReqs);

	VkMemoryAllocateInfo allocInfo = {};
	allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
	allocInfo.allocationSize = memReqs.size;
	allocInfo.memoryTypeIndex = findMemoryType(physDevice, memReqs.memoryTypeBits, memProps);
	VK_CHECK(vkAllocateMemory(device, &allocInfo, nullptr, &buf.memory));
	VK_CHECK(vkBindBufferMemory(device, buf.buffer, buf.memory, 0));

	if (memProps & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)
		VK_CHECK(vkMapMemory(device, buf.memory, 0, size, 0, &buf.mapped));

	return buf;
}

static void destroyBuffer(VkDevice device, VulkanBuffer &buf) {
	if (buf.mapped) vkUnmapMemory(device, buf.memory);
	vkDestroyBuffer(device, buf.buffer, nullptr);
	vkFreeMemory(device, buf.memory, nullptr);
}

static vector<uint8_t> readFile(const string &filename) {
	ifstream file(filename, ios::ate | ios::binary);
	if (!file.is_open()) {
		fprintf(stderr, "Failed to open file: %s\n", filename.c_str());
		exit(1);
	}
	size_t fileSize = (size_t)file.tellg();
	vector<uint8_t> buffer(fileSize);
	file.seekg(0);
	file.read((char*)buffer.data(), fileSize);
	file.close();
	return buffer;
}

// ── Main ─────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
	uint32_t RESULT_LOWEST[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint32_t DATA_LEN;

	int NUM_THREADS = 65536;
	int WORKGROUP_SIZE = 256;
	int EPOCH_COUNT = 100;

	int device_index = 0;
	if (argc > 1) { device_index = atoi(argv[1]); }
	if (argc > 2) { filename_log = argv[2]; logmode = 0; } else { filename_log = "log.txt"; }
	if (argc > 3) { filename_out = argv[3]; } else { filename_out = "result.txt"; }
	if (argc > 4) { g_nonce_start = atoi(argv[4]); }
	if (argc > 5) { g_nonce_end = atoi(argv[5]); }
	if (argc > 6) { g_target_zeros = atoi(argv[6]); }
	if (argc > 7) {
		g_target_prefix_str = argv[7];
		parse_hex_prefix(argv[7], g_prefix, g_prefix_mask);
		g_prefix_mode = 1;
	}

	// Read base.txt
	log_msg("Reading data");
	ifstream file_base;
	file_base.open("base.txt", ios::in | ios::binary | ios::ate);
	if (!file_base.is_open()) { log_msg("base.txt not found."); return 1; }
	DATA_LEN = file_base.tellg();

	uint32_t PADDED_LEN;
	if (DATA_LEN % 64 <= 55) PADDED_LEN = DATA_LEN / 64 * 64 + 64;
	else PADDED_LEN = DATA_LEN / 64 * 64 + 128;

	vector<uint8_t> DATA(PADDED_LEN, 0);
	vector<uint8_t> DATA_LOWEST(PADDED_LEN, 0);
	file_base.seekg(0, ios::beg);
	file_base.read((char*)DATA.data(), DATA_LEN);
	file_base.close();
	log_msg("Read " + to_string(DATA_LEN) + " bytes.");
	memcpy(DATA_LOWEST.data(), DATA.data(), DATA_LEN);

	uint32_t NONCE_LEN = g_nonce_end - g_nonce_start;
	int nonce_block_start = (g_nonce_start / 64) * 64;

	// Pad data on host
	int padded_len_int = (int)DATA_LEN;
	sha1_expand(DATA.data(), &padded_len_int);
	PADDED_LEN = (uint32_t)padded_len_int;

	// Pre-compute SHA-1 state for blocks before nonce block
	uint32_t state_cache[5];
	sha1_init(state_cache);
	for (int i = 0; i < nonce_block_start; i += 64)
		sha1_block(DATA.data() + i, state_cache);

	log_msg("Pre-computed SHA-1 cache for " + to_string(nonce_block_start / 64) + " blocks");
	log_msg("Remaining blocks per hash: " + to_string((PADDED_LEN - nonce_block_start) / 64));

	// Number of uints to store nonce bytes (packed)
	uint32_t nonce_uints = (NONCE_LEN + 3) / 4;

	// ── Vulkan instance ──
	VkApplicationInfo appInfo = {};
	appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
	appInfo.pApplicationName = "gitminer_vulkan";
	appInfo.applicationVersion = VK_MAKE_VERSION(1, 0, 0);
	appInfo.pEngineName = "No Engine";
	appInfo.engineVersion = VK_MAKE_VERSION(1, 0, 0);
	appInfo.apiVersion = VK_API_VERSION_1_0;

	VkInstanceCreateInfo instanceInfo = {};
	instanceInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
	instanceInfo.pApplicationInfo = &appInfo;

#ifdef __APPLE__
	instanceInfo.flags = VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR;
	const char *instanceExtensions[] = {
		VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME,
		VK_KHR_GET_PHYSICAL_DEVICE_PROPERTIES_2_EXTENSION_NAME
	};
	instanceInfo.enabledExtensionCount = 2;
	instanceInfo.ppEnabledExtensionNames = instanceExtensions;
#endif

	VkInstance instance;
	VK_CHECK(vkCreateInstance(&instanceInfo, nullptr, &instance));

	// ── Physical device ──
	uint32_t physDeviceCount = 0;
	VK_CHECK(vkEnumeratePhysicalDevices(instance, &physDeviceCount, nullptr));
	if (physDeviceCount == 0) { log_msg("No Vulkan devices found."); return 1; }

	vector<VkPhysicalDevice> physDevices(physDeviceCount);
	VK_CHECK(vkEnumeratePhysicalDevices(instance, &physDeviceCount, physDevices.data()));

	if (device_index < 0 || device_index >= (int)physDeviceCount) {
		log_msg("Invalid device index " + to_string(device_index) + " (found " + to_string(physDeviceCount) + " devices)");
		return 1;
	}

	VkPhysicalDevice physDevice = physDevices[device_index];
	VkPhysicalDeviceProperties deviceProps;
	vkGetPhysicalDeviceProperties(physDevice, &deviceProps);
	log_msg("Vulkan device: " + string(deviceProps.deviceName));

	// ── Queue family ──
	uint32_t queueFamilyCount = 0;
	vkGetPhysicalDeviceQueueFamilyProperties(physDevice, &queueFamilyCount, nullptr);
	vector<VkQueueFamilyProperties> queueFamilies(queueFamilyCount);
	vkGetPhysicalDeviceQueueFamilyProperties(physDevice, &queueFamilyCount, queueFamilies.data());

	uint32_t computeQueueFamily = UINT32_MAX;
	for (uint32_t i = 0; i < queueFamilyCount; i++) {
		if (queueFamilies[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
			computeQueueFamily = i;
			break;
		}
	}
	if (computeQueueFamily == UINT32_MAX) { log_msg("No compute queue family found."); return 1; }

	// ── Logical device ──
	float queuePriority = 1.0f;
	VkDeviceQueueCreateInfo queueInfo = {};
	queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
	queueInfo.queueFamilyIndex = computeQueueFamily;
	queueInfo.queueCount = 1;
	queueInfo.pQueuePriorities = &queuePriority;

	VkDeviceCreateInfo deviceInfo = {};
	deviceInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
	deviceInfo.queueCreateInfoCount = 1;
	deviceInfo.pQueueCreateInfos = &queueInfo;
#ifdef __APPLE__
	const char *deviceExtensions[] = { "VK_KHR_portability_subset" };
	deviceInfo.enabledExtensionCount = 1;
	deviceInfo.ppEnabledExtensionNames = deviceExtensions;
#else
	deviceInfo.enabledExtensionCount = 0;
	deviceInfo.ppEnabledExtensionNames = nullptr;
#endif

	VkDevice device;
	VK_CHECK(vkCreateDevice(physDevice, &deviceInfo, nullptr, &device));

	VkQueue computeQueue;
	vkGetDeviceQueue(device, computeQueueFamily, 0, &computeQueue);

	// ── Load SPIR-V shader ──
	auto shaderCode = readFile("sha1_kernel.spv");
	VkShaderModuleCreateInfo shaderInfo = {};
	shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
	shaderInfo.codeSize = shaderCode.size();
	shaderInfo.pCode = (const uint32_t*)shaderCode.data();

	VkShaderModule shaderModule;
	VK_CHECK(vkCreateShaderModule(device, &shaderInfo, nullptr, &shaderModule));

	// ── Descriptor set layout (7 storage buffers) ──
	VkDescriptorSetLayoutBinding bindings[7] = {};
	for (int i = 0; i < 7; i++) {
		bindings[i].binding = i;
		bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
		bindings[i].descriptorCount = 1;
		bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
	}

	VkDescriptorSetLayoutCreateInfo descLayoutInfo = {};
	descLayoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
	descLayoutInfo.bindingCount = 7;
	descLayoutInfo.pBindings = bindings;

	VkDescriptorSetLayout descSetLayout;
	VK_CHECK(vkCreateDescriptorSetLayout(device, &descLayoutInfo, nullptr, &descSetLayout));

	// ── Pipeline layout ──
	VkPipelineLayoutCreateInfo pipelineLayoutInfo = {};
	pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
	pipelineLayoutInfo.setLayoutCount = 1;
	pipelineLayoutInfo.pSetLayouts = &descSetLayout;

	VkPipelineLayout pipelineLayout;
	VK_CHECK(vkCreatePipelineLayout(device, &pipelineLayoutInfo, nullptr, &pipelineLayout));

	// ── Compute pipeline ──
	VkComputePipelineCreateInfo pipelineInfo = {};
	pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
	pipelineInfo.stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
	pipelineInfo.stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
	pipelineInfo.stage.module = shaderModule;
	pipelineInfo.stage.pName = "main";
	pipelineInfo.layout = pipelineLayout;

	VkPipeline pipeline;
	VK_CHECK(vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline));

	// ── Descriptor pool ──
	VkDescriptorPoolSize poolSize = {};
	poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
	poolSize.descriptorCount = 7;

	VkDescriptorPoolCreateInfo poolInfo = {};
	poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
	poolInfo.maxSets = 1;
	poolInfo.poolSizeCount = 1;
	poolInfo.pPoolSizes = &poolSize;

	VkDescriptorPool descPool;
	VK_CHECK(vkCreateDescriptorPool(device, &poolInfo, nullptr, &descPool));

	// ── Allocate descriptor set ──
	VkDescriptorSetAllocateInfo descAllocInfo = {};
	descAllocInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
	descAllocInfo.descriptorPool = descPool;
	descAllocInfo.descriptorSetCount = 1;
	descAllocInfo.pSetLayouts = &descSetLayout;

	VkDescriptorSet descSet;
	VK_CHECK(vkAllocateDescriptorSets(device, &descAllocInfo, &descSet));

	// ── Create buffers ──
	VkMemoryPropertyFlags hostVisible = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
	VkBufferUsageFlags storageUsage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;

	// Buffer 0: data_padded (padded input data as uints)
	uint32_t data_uint_count = (PADDED_LEN + 3) / 4;
	VulkanBuffer dataBuf = createBuffer(device, physDevice, data_uint_count * sizeof(uint32_t), storageUsage, hostVisible);

	// Buffer 1: state_cache (5 uints)
	VulkanBuffer stateBuf = createBuffer(device, physDevice, 5 * sizeof(uint32_t), storageUsage, hostVisible);

	// Buffer 2: nonces (packed as uints, NUM_THREADS * nonce_uints)
	VulkanBuffer nonceBuf = createBuffer(device, physDevice, (VkDeviceSize)NUM_THREADS * nonce_uints * sizeof(uint32_t), storageUsage, hostVisible);

	// Buffer 3: best_results (NUM_THREADS * 5 uints)
	VulkanBuffer resultBuf = createBuffer(device, physDevice, (VkDeviceSize)NUM_THREADS * 5 * sizeof(uint32_t), storageUsage, hostVisible);

	// Buffer 4: best_nonces (packed as uints, NUM_THREADS * nonce_uints)
	VulkanBuffer bestNonceBuf = createBuffer(device, physDevice, (VkDeviceSize)NUM_THREADS * nonce_uints * sizeof(uint32_t), storageUsage, hostVisible);

	// Buffer 5: params
	struct {
		uint32_t nonce_start;
		uint32_t nonce_end;
		uint32_t epoch_count;
		uint32_t nonce_block_start;
		uint32_t padded_len;
		uint32_t nonce_size;
		uint32_t prefix_mode;
		uint32_t prefix[5];
		uint32_t mask[5];
	} params = {
		(uint32_t)g_nonce_start, (uint32_t)g_nonce_end,
		(uint32_t)EPOCH_COUNT, (uint32_t)nonce_block_start,
		PADDED_LEN, NONCE_LEN,
		(uint32_t)g_prefix_mode,
		{g_prefix[0], g_prefix[1], g_prefix[2], g_prefix[3], g_prefix[4]},
		{g_prefix_mask[0], g_prefix_mask[1], g_prefix_mask[2], g_prefix_mask[3], g_prefix_mask[4]}
	};
	VulkanBuffer paramBuf = createBuffer(device, physDevice, sizeof(params), storageUsage, hostVisible);

	// Buffer 6: found_flag (1 uint)
	VulkanBuffer foundBuf = createBuffer(device, physDevice, sizeof(uint32_t), storageUsage, hostVisible);

	// ── Fill buffers ──

	// Data buffer: copy padded data as bytes into uint-packed buffer
	memset(dataBuf.mapped, 0, data_uint_count * sizeof(uint32_t));
	memcpy(dataBuf.mapped, DATA.data(), PADDED_LEN);

	// State cache
	memcpy(stateBuf.mapped, state_cache, 5 * sizeof(uint32_t));

	// Initialize nonces (pack bytes into uints)
	{
		uint32_t *nonce_ptr = (uint32_t*)nonceBuf.mapped;
		memset(nonce_ptr, 0, (size_t)NUM_THREADS * nonce_uints * sizeof(uint32_t));
		vector<uint8_t> tmp_nonce(NONCE_LEN);
		for (int i = 0; i < NUM_THREADS; i++) {
			init_nonce(tmp_nonce.data(), NONCE_LEN);
			// Pack bytes into uints
			uint32_t *dst = nonce_ptr + i * nonce_uints;
			for (uint32_t b = 0; b < NONCE_LEN; b++) {
				uint32_t word_idx = b / 4;
				uint32_t byte_off = (b % 4) * 8;
				dst[word_idx] |= (uint32_t)tmp_nonce[b] << byte_off;
			}
		}
	}

	// Initialize results to 0xff
	memset(resultBuf.mapped, 0xff, (size_t)NUM_THREADS * 5 * sizeof(uint32_t));

	// Params
	memcpy(paramBuf.mapped, &params, sizeof(params));

	// Found flag
	memset(foundBuf.mapped, 0, sizeof(uint32_t));

	// ── Update descriptor set ──
	VkDescriptorBufferInfo bufInfos[7] = {};
	bufInfos[0] = {dataBuf.buffer, 0, dataBuf.size};
	bufInfos[1] = {stateBuf.buffer, 0, stateBuf.size};
	bufInfos[2] = {nonceBuf.buffer, 0, nonceBuf.size};
	bufInfos[3] = {resultBuf.buffer, 0, resultBuf.size};
	bufInfos[4] = {bestNonceBuf.buffer, 0, bestNonceBuf.size};
	bufInfos[5] = {paramBuf.buffer, 0, paramBuf.size};
	bufInfos[6] = {foundBuf.buffer, 0, foundBuf.size};

	VkWriteDescriptorSet descWrites[7] = {};
	for (int i = 0; i < 7; i++) {
		descWrites[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
		descWrites[i].dstSet = descSet;
		descWrites[i].dstBinding = i;
		descWrites[i].dstArrayElement = 0;
		descWrites[i].descriptorCount = 1;
		descWrites[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
		descWrites[i].pBufferInfo = &bufInfos[i];
	}
	vkUpdateDescriptorSets(device, 7, descWrites, 0, nullptr);

	// ── Command pool and buffer ──
	VkCommandPoolCreateInfo cmdPoolInfo = {};
	cmdPoolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
	cmdPoolInfo.queueFamilyIndex = computeQueueFamily;
	cmdPoolInfo.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;

	VkCommandPool cmdPool;
	VK_CHECK(vkCreateCommandPool(device, &cmdPoolInfo, nullptr, &cmdPool));

	VkCommandBufferAllocateInfo cmdBufAllocInfo = {};
	cmdBufAllocInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
	cmdBufAllocInfo.commandPool = cmdPool;
	cmdBufAllocInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
	cmdBufAllocInfo.commandBufferCount = 1;

	VkCommandBuffer cmdBuf;
	VK_CHECK(vkAllocateCommandBuffers(device, &cmdBufAllocInfo, &cmdBuf));

	// ── Fence for synchronization ──
	VkFenceCreateInfo fenceInfo = {};
	fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
	VkFence fence;
	VK_CHECK(vkCreateFence(device, &fenceInfo, nullptr, &fence));

	// ── Logging setup ──
	uint32_t numGroups = (NUM_THREADS + WORKGROUP_SIZE - 1) / WORKGROUP_SIZE;
	log_msg("Using " + to_string(NUM_THREADS) + " GPU threads (" +
		to_string(WORKGROUP_SIZE) + " per workgroup, " + to_string(numGroups) + " groups)");
	log_msg("Nonce region: [" + to_string(g_nonce_start) + ", " + to_string(g_nonce_end) + ")");
	if (g_prefix_mode)
		log_msg("Target prefix: " + g_target_prefix_str);
	else if (g_target_zeros > 0)
		log_msg("Target: " + to_string(g_target_zeros) + " leading hex zeros");

	auto begin = chrono::high_resolution_clock::now();
	auto begin_log = chrono::high_resolution_clock::now();
	uint64_t processed = 0, processed_last = 0;
	char buf[1000];
	bool found = false;

	log_msg("Launching Vulkan compute");

	for (;;) {
		// Reset found flag
		*((uint32_t*)foundBuf.mapped) = 0;

		// Record command buffer
		VkCommandBufferBeginInfo beginInfo = {};
		beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
		beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
		VK_CHECK(vkBeginCommandBuffer(cmdBuf, &beginInfo));

		vkCmdBindPipeline(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
		vkCmdBindDescriptorSets(cmdBuf, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout, 0, 1, &descSet, 0, nullptr);
		vkCmdDispatch(cmdBuf, numGroups, 1, 1);

		VK_CHECK(vkEndCommandBuffer(cmdBuf));

		// Submit
		VkSubmitInfo submitInfo = {};
		submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
		submitInfo.commandBufferCount = 1;
		submitInfo.pCommandBuffers = &cmdBuf;

		VK_CHECK(vkResetFences(device, 1, &fence));
		VK_CHECK(vkQueueSubmit(computeQueue, 1, &submitInfo, fence));
		VK_CHECK(vkWaitForFences(device, 1, &fence, VK_TRUE, UINT64_MAX));

		processed += (uint64_t)NUM_THREADS * EPOCH_COUNT * (range_upper - range_lower + 1);

		// Read back results
		uint32_t *results = (uint32_t*)resultBuf.mapped;
		uint32_t *bestNonces = (uint32_t*)bestNonceBuf.mapped;

		for (int i = 0; i < NUM_THREADS; i++) {
			if (g_prefix_mode) {
				bool match = true;
				for (int k = 0; k < 5; k++) {
					if ((results[i * 5 + k] & g_prefix_mask[k]) != g_prefix[k]) {
						match = false;
						break;
					}
				}
				if (match) {
					memcpy(RESULT_LOWEST, results + i * 5, 5 * 4);

					// Unpack nonce bytes from uints
					uint32_t *src_nonce = bestNonces + i * nonce_uints;
					for (uint32_t j = 0; j < NONCE_LEN; j++) {
						uint32_t word_idx = j / 4;
						uint32_t byte_off = (j % 4) * 8;
						DATA_LOWEST[g_nonce_start + j] = (src_nonce[word_idx] >> byte_off) & 0xFF;
					}

					char buf_nonce[256];
					for (uint32_t j = 0; j < NONCE_LEN; j++)
						buf_nonce[j] = DATA_LOWEST[g_nonce_start + j];
					buf_nonce[NONCE_LEN] = 0;
					snprintf(buf, sizeof(buf),
						"Found prefix match: %08x%08x%08x%08x%08x (nonce: %s)",
						RESULT_LOWEST[0], RESULT_LOWEST[1], RESULT_LOWEST[2],
						RESULT_LOWEST[3], RESULT_LOWEST[4], buf_nonce);
					log_msg(buf);

					ofstream file_out;
					file_out.open(filename_out, ios::out | ios::binary);
					file_out.write((char*)DATA_LOWEST.data(), DATA_LEN);
					file_out.close();

					found = true;
				}
			} else {
				if (is_lower_hash(results + i * 5, RESULT_LOWEST)) {
					memcpy(RESULT_LOWEST, results + i * 5, 5 * 4);

					// Unpack nonce bytes from uints
					uint32_t *src_nonce = bestNonces + i * nonce_uints;
					for (uint32_t j = 0; j < NONCE_LEN; j++) {
						uint32_t word_idx = j / 4;
						uint32_t byte_off = (j % 4) * 8;
						DATA_LOWEST[g_nonce_start + j] = (src_nonce[word_idx] >> byte_off) & 0xFF;
					}

					char buf_nonce[256];
					for (uint32_t j = 0; j < NONCE_LEN; j++)
						buf_nonce[j] = DATA_LOWEST[g_nonce_start + j];
					buf_nonce[NONCE_LEN] = 0;
					snprintf(buf, sizeof(buf),
						"Found new lowest: %08x%08x%08x%08x%08x (nonce: %s)",
						RESULT_LOWEST[0], RESULT_LOWEST[1], RESULT_LOWEST[2],
						RESULT_LOWEST[3], RESULT_LOWEST[4], buf_nonce);
					log_msg(buf);

					ofstream file_out;
					file_out.open(filename_out, ios::out | ios::binary);
					file_out.write((char*)DATA_LOWEST.data(), DATA_LEN);
					file_out.close();

					if (g_target_zeros > 0 && has_leading_zeros(RESULT_LOWEST, g_target_zeros))
						found = true;
				}
			}
		}

		if (found) {
			log_msg("Target reached! Exiting.");
			break;
		}

		auto end = chrono::high_resolution_clock::now();
		double elapsed_log_s = chrono::duration<double>(end - begin_log).count();
		if (elapsed_log_s >= 5.0) {
			double rate = (double)(processed - processed_last) / elapsed_log_s;
			snprintf(buf, sizeof(buf), "Processed %" PRIu64 "G hashes (%.2fMH/s)",
				processed / 1000000000, rate / 1e6);
			processed_last = processed;
			log_msg(buf);
			begin_log = chrono::high_resolution_clock::now();
		}
	}

	// ── Cleanup ──
	vkDestroyFence(device, fence, nullptr);
	vkFreeCommandBuffers(device, cmdPool, 1, &cmdBuf);
	vkDestroyCommandPool(device, cmdPool, nullptr);
	destroyBuffer(device, dataBuf);
	destroyBuffer(device, stateBuf);
	destroyBuffer(device, nonceBuf);
	destroyBuffer(device, resultBuf);
	destroyBuffer(device, bestNonceBuf);
	destroyBuffer(device, paramBuf);
	destroyBuffer(device, foundBuf);
	vkDestroyPipeline(device, pipeline, nullptr);
	vkDestroyPipelineLayout(device, pipelineLayout, nullptr);
	vkDestroyDescriptorPool(device, descPool, nullptr);
	vkDestroyDescriptorSetLayout(device, descSetLayout, nullptr);
	vkDestroyShaderModule(device, shaderModule, nullptr);
	vkDestroyDevice(device, nullptr);
	vkDestroyInstance(instance, nullptr);

	return 0;
}
