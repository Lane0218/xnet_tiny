#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>

// xnet_tiny网络库配置常量
#define XNET_CFG_NETIF_IP {192, 168, 254, 2} // 本机网卡IP地址配置
#define XNET_CFG_PACKET_MAX_SIZE 1516        // 收发数据包的最大大小，以字节为单位
#define XARP_CFG_ENTRY_OK_TMO (5)            // ARP表项超时时间，单位为秒
#define XARP_CFG_ENTRY_PENDING_TMO (1)       // ARP表项挂起超时时间，单位为秒
#define XARP_CFG_MAX_RETRIES 4               // ARP表挂起时重试查询次数

#pragma pack(1)

#define XNET_IPV4_ADDR_SIZE 4 // IPv4地址长度，为4字节
#define XNET_MAC_ADDR_SIZE 6  // MAC地址长度，为6字节

/**
 * 以太网数据帧格式：遵循RFC894标准
 */
typedef struct _xether_hdr_t
{
    uint8_t dest[XNET_MAC_ADDR_SIZE]; // 目标MAC地址
    uint8_t src[XNET_MAC_ADDR_SIZE];  // 源MAC地址
    uint16_t protocol;                // 协议类型或长度字段
} xether_hdr_t;

#define XARP_HW_ETHER 0x1 // 以太网硬件类型
#define XARP_REQUEST 0x1  // ARP请求包操作码
#define XARP_REPLY 0x2    // ARP响应包操作码

/**
 * ARP包结构，用于封装ARP请求和响应的数据
 */
typedef struct _xarp_packet_t
{
    uint16_t hw_type, pro_type;             // 硬件类型和协议类型
    uint8_t hw_len, pro_len;                // 硬件地址长度和协议地址长度
    uint16_t opcode;                        // 请求/响应操作码
    uint8_t sender_mac[XNET_MAC_ADDR_SIZE]; // 发送者硬件地址（MAC地址）
    uint8_t sender_ip[XNET_IPV4_ADDR_SIZE]; // 发送者协议地址（IPv4地址）
    uint8_t target_mac[XNET_MAC_ADDR_SIZE]; // 目标硬件地址（MAC地址）
    uint8_t target_ip[XNET_IPV4_ADDR_SIZE]; // 目标协议地址（IPv4地址）
} xarp_packet_t;

/**
 * IPv4头部结构，用于封装IPv4数据包的头部信息
 */
typedef struct _xip_hdr_t
{
    uint8_t hdr_len : 4;                  // 首部长度，以4字节为单位
    uint8_t version : 4;                  // 版本号，IPv4
    uint8_t tos;                          // 服务类型
    uint16_t total_len;                   // 总长度
    uint16_t id;                          // 标识符
    uint16_t flags_fragment;              // 标志与分段
    uint8_t ttl;                          // 存活时间
    uint8_t protocol;                     // 上层协议
    uint16_t hdr_checksum;                // 首部校验和
    uint8_t src_ip[XNET_IPV4_ADDR_SIZE];  // 源IPv4地址
    uint8_t dest_ip[XNET_IPV4_ADDR_SIZE]; // 目标IPv4地址
} xip_hdr_t;

/**
 * ICMP报文头结构，用于封装ICMP消息的头部信息
 */
typedef struct _xicmp_hdr_t
{
    uint8_t type;      // ICMP消息类型，定义了ICMP报文的种类
    uint8_t code;      // ICMP代码，提供类型进一步的信息
    uint16_t checksum; // ICMP报文的校验和，用于检测传输过程中的错误
    uint16_t id;       // 标识符，用于区分不同的ICMP请求和响应
    uint16_t seq;      // 序号，用于区分同一ICMP请求中的不同报文
} xicmp_hdr_t;

#pragma pack()

/**
 * 网络错误码枚举，定义了网络操作可能返回的错误类型
 */
typedef enum _xnet_err_t
{
    XNET_ERR_OK = 0,    // 无错误，操作成功
    XNET_ERR_IO = -1,   // 输入输出错误，表示硬件层面的通信错误
    XNET_ERR_NONE = -2, // 函数执行成功但没有特定值返回
} xnet_err_t;

/**
 * 网络数据结构，用于存储网络包
 */
typedef struct _xnet_packet_t
{
    uint16_t size;                             // 包中有效数据的大小
    uint8_t *data;                             // 包的数据起始地址
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE]; // 最大负载数据量
} xnet_packet_t;

typedef uint32_t xnet_time_t; // 时间类型，返回当前系统跑了多少个100ms周期

/**
 * 获取当前系统时间，单位为100ms周期
 */
const xnet_time_t xsys_get_time(void);

/**
 * 检查是否超时，参数为指向时间的指针和超时秒数
 */
int xnet_check_tmo(xnet_time_t *time, uint32_t sec);

/**
 * 分配用于发送的网络包，参数为数据大小
 */
xnet_packet_t *xnet_alloc_for_send(uint16_t data_size);

/**
 * 分配用于接收的网络包，参数为数据大小
 */
xnet_packet_t *xnet_alloc_for_read(uint16_t data_size);

/**
 * 打开网络驱动，配置MAC地址，参数为MAC地址
 */
xnet_err_t xnet_driver_open(uint8_t *mac_addr);

/**
 * 通过网络驱动发送数据包，参数为指向网络包的指针
 */
xnet_err_t xnet_driver_send(xnet_packet_t *packet);

/**
 * 从网络驱动读取数据包，参数为指向网络包指针的指针
 */
xnet_err_t xnet_driver_read(xnet_packet_t **packet);

/**
 * 网络协议枚举，定义了支持的网络协议类型
 */
typedef enum _xnet_protocol_t
{
    XNET_PROTOCOL_ARP = 0x0806, // ARP协议类型
    XNET_PROTOCOL_IP = 0x0800,  // IP协议类型
    XNET_PROTOCOL_ICMP = 1,     // ICMP协议类型
} xnet_protocol_t;

/**
 * IPv4地址表示，可以作为字节数组或32位整数
 */
typedef union _xipaddr_t
{
    uint8_t array[XNET_IPV4_ADDR_SIZE]; // 以字节数组形式存储的IPv4地址
    uint32_t addr;                      // 以32位整数形式存储的IPv4地址
} xipaddr_t;

#define XARP_ENTRY_FREE 0      // ARP表项空闲状态
#define XARP_ENTRY_OK 1        // ARP表项解析成功状态
#define XARP_ENTRY_RESOLVING 2 // ARP表项正在解析状态
#define XARP_TIMER_PERIOD 1    // ARP扫描周期，单位为秒

/**
 * ARP表项结构，用于存储ARP解析过程中的信息
 */
typedef struct _xarp_entry_t
{
    xipaddr_t ipaddr;                    // IPv4地址
    uint8_t macaddr[XNET_MAC_ADDR_SIZE]; // MAC地址
    uint8_t state;                       // 状态位
    uint16_t tmo;                        // 当前超时时间
    uint8_t retry_cnt;                   // 当前重试次数
} xarp_entry_t;

/**
 * 初始化ARP模块
 */
void xarp_init(void);
/**
 * 创建ARP请求
 */
xnet_err_t xarp_make_request(const xipaddr_t *ipaddr);
/**
 * 处理接收到的ARP包
 */
void xarp_in(xnet_packet_t *packet);
/**
 * 解析IP地址对应的MAC地址
 */
xnet_err_t xarp_resolve(const xipaddr_t *ipaddr, uint8_t **mac_addr);

/**
 * ARP模块轮询函数
 */
void xarp_poll(void);

#define XNET_VERSION_IPV4 4    // IPv4版本
#define XNET_IP_DEFAULT_TTL 64 // 缺省的IP包TTL值
/**
 * 初始化IP模块
 */
void xip_init(void);
/**
 * 处理接收到的IP包
 */
void xip_in(xnet_packet_t *packet);
/**
 * 向外发送IP包
 */
xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t *dest_ip, xnet_packet_t *packet);

#define XICMP_CODE_ECHO_REQUEST 8 // ICMP回显请求代码
#define XICMP_CODE_ECHO_REPLY 0   // ICMP回显响应代码
#define XICMP_TYPE_UNREACH 3      // ICMP目的不可达类型
#define XICMP_CODE_PORT_UNREACH 3 // ICMP端口不可达代码
#define XICMP_CODE_PRO_UNREACH 2  // ICMP协议不可达代码
/**
 * 初始化ICMP模块
 */
void xicmp_init(void);
/**
 * 处理接收到的ICMP包
 */
void xicmp_in(xipaddr_t *src_ip, xnet_packet_t *packet);
/**
 * 发送ICMP目的不可达报文
 */
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t *ip_hdr);

/**
 * 初始化网络模块
 */
void xnet_init(void);
/**
 * 网络模块轮询函数
 */
void xnet_poll(void);

#endif // XNET_TINY_H