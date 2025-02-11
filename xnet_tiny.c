#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "xnet_tiny.h"

#define min(a, b) ((a) > (b) ? (b) : (a)) // 定义宏min，返回两个参数中的较小值

// 定义全局变量
static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;                       // 本机网卡IP地址
static const uint8_t ether_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // 广播MAC地址
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];                                  // 本机MAC地址
static xnet_packet_t tx_packet, rx_packet;                                     // 发送和接收数据包缓冲区
static xarp_entry_t arp_entry;                                                 // ARP表项，用于存储IP与MAC的映射关系
static xnet_time_t arp_timer;                                                  // ARP表项超时计时器

// 更新ARP表项的函数声明
static void update_arp_entry(uint8_t *src_ip, uint8_t *mac_addr);

// 以下为一些辅助宏定义
#define swap_order16(v) ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))                              // 交换16位数值的字节序
#define xipaddr_is_equal_buf(addr, buf) (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0) // 比较IPv4地址是否相等
#define xipaddr_is_equal(addr1, addr2) ((addr1)->addr == (addr2)->addr)                          // 比较两个IPv4地址是否相等
#define xipaddr_from_buf(dest, buf) ((dest)->addr = *(uint32_t *)(buf))                          // 从字节缓冲区复制IPv4地址

/**
 * 检查是否超时
 * @param time 指向存储上一次时间的指针
 * @param sec 预期超时时间，值为0时，表示获取当前时间
 * @return 0 - 未超时，1-超时
 */
int xnet_check_tmo(xnet_time_t *time, uint32_t sec)
{
    xnet_time_t curr = xsys_get_time(); // 获取当前系统时间
    if (sec == 0)
    { // 如果参数为0，仅更新时间并返回未超时
        *time = curr;
        return 0;
    }
    else if (curr - *time >= sec)
    {                 // 检查当前时间与上次时间的差是否达到或超过预期超时时间
        *time = curr; // 更新时间
        return 1;
    }
    return 0;
}

/**
 * 分配一个网络数据包用于发送数据
 * @param data_size 数据空间大小
 * @return 分配得到的包结构
 */
xnet_packet_t *xnet_alloc_for_send(uint16_t data_size)
{
    // 从发送缓冲区的末尾向前分配空间，为协议头部留出空间
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
    tx_packet.size = data_size;
    return &tx_packet;
}

/**
 * 分配一个网络数据包用于读取
 * @param data_size 数据空间大小
 * @return 分配得到的数据包
 */
xnet_packet_t *xnet_alloc_for_read(uint16_t data_size)
{
    // 从接收缓冲区的开始处分配空间，用于读取网络帧
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    return &rx_packet;
}

/**
 * 为发包添加一个头部
 * @param packet 待处理的数据包
 * @param header_size 增加的头部大小
 */
static void add_header(xnet_packet_t *packet, uint16_t header_size)
{
    packet->data -= header_size; // 将数据指针向前移动，为新头部腾出空间
    packet->size += header_size; // 更新数据包大小
}

/**
 * 为接收向上处理移去头部
 * @param packet 待处理的数据包
 * @param header_size 移去的头部大小
 */
static void remove_header(xnet_packet_t *packet, uint16_t header_size)
{
    packet->data += header_size; // 将数据指针向后移动，移除头部
    packet->size -= header_size; // 更新数据包大小
}

/**
 * 将包的长度截断为size大小
 * @param packet 待处理的数据包
 * @param size 最终大小
 */
static void truncate_packet(xnet_packet_t *packet, uint16_t size)
{
    packet->size = min(packet->size, size); // 将数据包大小截断为指定大小
}

/**
 * 以太网初始化
 * @return 初始化结果
 */
static xnet_err_t ethernet_init(void)
{
    xnet_err_t err = xnet_driver_open(netif_mac); // 打开网络驱动
    if (err < 0)
        return err;

    // 发送ARP请求以宣告本机IP地址
    return xarp_make_request(&netif_ipaddr);
}

/**
 * 发送一个以太网数据帧
 * @param protocol 上层数据协议，IP或ARP
 * @param mac_addr 目标网卡的mac地址
 * @param packet 待发送的数据包
 * @return 发送结果
 */
static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t *packet)
{
    xether_hdr_t *ether_hdr;

    // 添加以太网头部
    add_header(packet, sizeof(xether_hdr_t));
    ether_hdr = (xether_hdr_t *)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE); // 目标MAC地址
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE); // 源MAC地址
    ether_hdr->protocol = swap_order16(protocol);          // 协议类型，需要交换字节序

    // 数据发送
    return xnet_driver_send(packet);
}

/**
 * 将IP数据包通过以太网发送出去
 * @param dest_ip 目标IP地址
 * @param packet 待发送IP数据包
 * @return 发送结果
 */
static xnet_err_t ethernet_out(xipaddr_t *dest_ip, xnet_packet_t *packet)
{
    xnet_err_t err;
    uint8_t *mac_addr;

    // 尝试解析目标IP地址对应的MAC地址
    if ((err = xarp_resolve(dest_ip, &mac_addr)) == XNET_ERR_OK)
    {
        return ethernet_out_to(XNET_PROTOCOL_IP, mac_addr, packet); // 通过以太网发送IP数据包
    }
    return err;
}

/**
 * 以太网数据帧输入输出
 * @param packet 待处理的包
 */
static void ethernet_in(xnet_packet_t *packet)
{
    // 如果数据包太小，不足以包含以太网头部，则丢弃
    if (packet->size <= sizeof(xether_hdr_t))
    {
        return;
    }

    // 根据以太网头部的协议类型，将数据包传递给相应的协议处理函数
    xether_hdr_t *hdr = (xether_hdr_t *)packet->data;
    switch (swap_order16(hdr->protocol))
    {
    case XNET_PROTOCOL_ARP:
        remove_header(packet, sizeof(xether_hdr_t)); // 移除以太网头部
        xarp_in(packet);                             // 处理ARP数据包
        break;
    case XNET_PROTOCOL_IP:
    {
        // 提取IP头部和MAC地址，并更新ARP表
#if 0
         xip_hdr_t *iphdr = (xip_hdr_t *) (packet->data + sizeof(xether_hdr_t));
            if (packet->size >= sizeof(xether_hdr_t) + sizeof(xip_hdr_t)) {
                if (memcmp(iphdr->dest_ip, &netif_ipaddr.array, XNET_IPV4_ADDR_SIZE) == 0) {
                    update_arp_entry(iphdr->src_ip, hdr->src);
                }
            }
#endif
        remove_header(packet, sizeof(xether_hdr_t)); // 移除以太网头部
        xip_in(packet);                              // 处理IP数据包
        break;
    }
    }
}

/**
 * 查询网络接口，看看是否有数据包，有则进行处理
 */
static void ethernet_poll(void)
{
    xnet_packet_t *packet;

    // 从网络驱动读取数据包
    if (xnet_driver_read(&packet) == XNET_ERR_OK)
    {
        // 处理接收到的数据包
        ethernet_in(packet);
    }
}

/**
 * ARP初始化
 */
void xarp_init(void)
{
    arp_entry.state = XARP_ENTRY_FREE; // 初始化ARP表项状态为空闲

    // 获取初始时间
    xnet_check_tmo(&arp_timer, 0);
}

/**
 * 查询ARP表项是否超时，超时则重新请求
 */
void xarp_poll(void)
{
    if (xnet_check_tmo(&arp_timer, XARP_TIMER_PERIOD)) // 检查是否到达ARP扫描周期
    {
        switch (arp_entry.state) // 根据ARP表项状态进行处理
        {
        case XARP_ENTRY_RESOLVING:
            if (--arp_entry.tmo == 0) // 检查ARP请求是否超时
            {                         // 重试完毕，回收
                if (arp_entry.retry_cnt-- == 0)
                {
                    arp_entry.state = XARP_ENTRY_FREE;
                }
                else
                { // 继续重试
                    xarp_make_request(&arp_entry.ipaddr);
                    arp_entry.state = XARP_ENTRY_RESOLVING;
                    arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
                }
            }
            break;
        case XARP_ENTRY_OK:
            if (--arp_entry.tmo == 0) // 检查ARP表项是否超时
            {                         // 超时，重新请求
                xarp_make_request(&arp_entry.ipaddr);
                arp_entry.state = XARP_ENTRY_RESOLVING;
                arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
            }
            break;
        }
    }
}

/**
 * 生成一个ARP响应
 * @param arp_packet 接收到的ARP请求包
 * @return 生成结果
 * 说明：
 *  1. 分配一个ARP响应包
 *  2. 将ARP请求包的目标MAC地址和目标IP地址，复制到ARP响应包的源MAC地址和源IP地址
 *  3. 将本机的MAC地址和IP地址，复制到ARP响应包的目标MAC地址和目标IP地址
 *  4. 通过以太网发送ARP响应包
 */
xnet_err_t xarp_make_response(xarp_packet_t *arp_packet)
{
    xarp_packet_t *response_packet;
    xnet_packet_t *packet = xnet_alloc_for_send(sizeof(xarp_packet_t));

    response_packet = (xarp_packet_t *)packet->data;
    response_packet->hw_type = swap_order16(XARP_HW_ETHER);
    response_packet->pro_type = swap_order16(XNET_PROTOCOL_IP);
    response_packet->hw_len = XNET_MAC_ADDR_SIZE;
    response_packet->pro_len = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode = swap_order16(XARP_REPLY);
    // 将ARP请求包的目标MAC地址和目标IP地址，复制到ARP响应包的源MAC地址和源IP地址
    memcpy(response_packet->target_mac, arp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, arp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);
    // 将本机的MAC地址和IP地址，复制到ARP响应包的目标MAC地址和目标IP地址
    memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);

    // 通过以太网发送ARP响应包
    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

/**
 * 产生一个ARP请求，请求网络指定IP地址的机器发回一个ARP响应
 * @param ipaddr 请求的IP地址
 * @return 请求结果
 */
xnet_err_t xarp_make_request(const xipaddr_t *ipaddr)
{
    xarp_packet_t *arp_packet;
    xnet_packet_t *packet = xnet_alloc_for_send(sizeof(xarp_packet_t)); // 分配一个用于发送的网络数据包

    arp_packet = (xarp_packet_t *)packet->data;                             // 获取ARP包的存储位置
    arp_packet->hw_type = swap_order16(XARP_HW_ETHER);                      // 设置硬件类型为以太网，转换字节序
    arp_packet->pro_type = swap_order16(XNET_PROTOCOL_IP);                  // 设置协议类型为IP，转换字节序
    arp_packet->hw_len = XNET_MAC_ADDR_SIZE;                                // 设置硬件地址长度
    arp_packet->pro_len = XNET_IPV4_ADDR_SIZE;                              // 设置协议地址长度
    arp_packet->opcode = swap_order16(XARP_REQUEST);                        // 设置操作码为ARP请求，转换字节序
    memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);          // 设置发送者MAC地址为本机MAC地址
    memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE); // 设置发送者IP地址为本机IP地址
    memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);                  // 将目标MAC地址清零
    memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);      // 设置目标IP地址为请求的IP地址
    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);     // 通过以太网发送ARP请求包，目标是广播地址
}

/**
 * 解析指定的IP地址，如果不在ARP表项中，则发送ARP请求
 * @param ipaddr 查找的ip地址
 * @param mac_addr 返回的mac地址存储区
 * @return XNET_ERR_OK 查找成功，XNET_ERR_NONE 查找失败
 */
xnet_err_t xarp_resolve(const xipaddr_t *ipaddr, uint8_t **mac_addr)
{
    if ((arp_entry.state == XARP_ENTRY_OK) && xipaddr_is_equal(ipaddr, &arp_entry.ipaddr))
    {
        *mac_addr = arp_entry.macaddr; // 如果ARP表项存在，则返回对应的MAC地址
        return XNET_ERR_OK;
    }

    xarp_make_request(ipaddr); // 如果ARP表项不存在，则发送ARP请求
    return XNET_ERR_NONE;
}

/**
 * 更新ARP表项
 * @param src_ip 源IP地址
 * @param mac_addr 对应的mac地址
 */
static void update_arp_entry(uint8_t *src_ip, uint8_t *mac_addr)
{
    memcpy(arp_entry.ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE); // 更新IP地址
    memcpy(arp_entry.macaddr, mac_addr, 6);                      // 更新MAC地址
    arp_entry.state = XARP_ENTRY_OK;                             // 设置ARP表项状态为解析成功
    arp_entry.tmo = XARP_CFG_ENTRY_OK_TMO;                       // 设置ARP表项超时时间
    arp_entry.retry_cnt = XARP_CFG_MAX_RETRIES;                  // 设置ARP表项重试次数
}

/**
 * ARP输入处理
 * @param packet 输入的ARP包
 */
void xarp_in(xnet_packet_t *packet)
{
    if (packet->size >= sizeof(xarp_packet_t)) // 如果数据包足够大，包含完整的ARP头部
    {
        xarp_packet_t *arp_packet = (xarp_packet_t *)packet->data;
        uint16_t opcode = swap_order16(arp_packet->opcode); // 获取ARP操作码

        // 包的合法性检查
        if ((swap_order16(arp_packet->hw_type) != XARP_HW_ETHER) ||
            (arp_packet->hw_len != XNET_MAC_ADDR_SIZE) ||
            (swap_order16(arp_packet->pro_type) != XNET_PROTOCOL_IP) ||
            (arp_packet->pro_len != XNET_IPV4_ADDR_SIZE) || ((opcode != XARP_REQUEST) && (opcode != XARP_REPLY)))
        {
            return;
        }

        // 只处理发给自己的请求或响应包
        if (!xipaddr_is_equal_buf(&netif_ipaddr, arp_packet->target_ip))
        {
            return;
        }

        // 根据操作码进行不同的处理
        switch (swap_order16(arp_packet->opcode))
        {
        case XARP_REQUEST: // 请求，回送响应
            // 在对方机器Ping 自己，然后看wireshark，能看到ARP请求和响应
            // 接下来，很可能对方要与自己通信，所以更新一下
            xarp_make_response(arp_packet);                                  // 生成ARP响应
            update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac); // 更新ARP表项
            break;
        case XARP_REPLY:                                                     // 响应，更新自己的表
            update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac); // 更新ARP表项
            break;
        }
    }
}

/**
 * 校验和计算
 * @param buf 校验数据区的起始地址
 * @param len 数据区的长度，以字节为单位
 * @param pre_sum 累加的之前的值，用于多次调用checksum对不同的的数据区计算出一个校验和
 * @param complement 是否对累加和的结果进行取反
 * @return 校验和结果
 */
static uint16_t checksum16(uint16_t *buf, uint16_t len, uint16_t pre_sum, int complement)
{
    uint32_t checksum = pre_sum; // 初始化校验和
    uint16_t high;

    while (len > 1) // 循环累加16位数据
    {
        checksum += *buf++;
        len -= 2;
    }
    if (len > 0) // 如果有剩余的字节，将其加入校验和计算
    {
        checksum += *(uint8_t *)buf;
    }

    // 将校验和的高16位和低16位相加，直到没有进位
    while ((high = checksum >> 16) != 0)
    {
        checksum = high + (checksum & 0xffff);
    }
    return complement ? (uint16_t)~checksum : (uint16_t)checksum; // 返回最终的校验和，根据参数决定是否取反
}

/**
 * IP层的初始化
 */
void xip_init(void) {}

/**
 * IP层的输入处理
 * @param packet 输入的IP数据包
 */
void xip_in(xnet_packet_t *packet)
{
    xip_hdr_t *iphdr = (xip_hdr_t *)packet->data; // 获取IP头部
    uint32_t total_size, header_size;
    uint16_t pre_checksum;
    xipaddr_t src_ip;

    // 进行一些必要性的检查：版本号要求
    if (iphdr->version != XNET_VERSION_IPV4)
    {
        return;
    }

    // 长度要求检查
    header_size = iphdr->hdr_len * 4;            // 计算IP头部长度
    total_size = swap_order16(iphdr->total_len); // 计算IP数据包总长度
    if ((header_size < sizeof(xip_hdr_t)) || ((total_size < header_size) || (packet->size < total_size)))
    {
        return;
    }

    // 校验和要求检查
    pre_checksum = iphdr->hdr_checksum;                                   // 保存原始校验和
    iphdr->hdr_checksum = 0;                                              // 清零校验和
    if (pre_checksum != checksum16((uint16_t *)iphdr, header_size, 0, 1)) // 计算校验和
    {
        return;
    }
    iphdr->hdr_checksum = pre_checksum; // 恢复原始校验和

    // 只处理目标IP为自己的数据包，其它广播之类的IP全部丢掉
    if (!xipaddr_is_equal_buf(&netif_ipaddr, iphdr->dest_ip))
    {
        return;
    }

    xipaddr_from_buf(&src_ip, iphdr->src_ip); // 获取源IP地址
    switch (iphdr->protocol)                  // 根据协议类型处理数据包
    {
    case XNET_PROTOCOL_ICMP:
        remove_header(packet, header_size); // 移除IP头部
        xicmp_in(&src_ip, packet);          // 处理ICMP数据包
        break;
    default:
        // 这里应当写成协议不可达，因为没有任何协议能处理输入数据包
        xicmp_dest_unreach(XICMP_CODE_PRO_UNREACH, iphdr); // 发送协议不可达报文
        break;
    }
}

/**
 * IP包的输出
 * @param protocol 上层协议，ICMP、UDP或TCP
 * @param dest_ip 目标IP地址
 * @param packet 待发送的数据包
 * @return 发送结果
 */
xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t *dest_ip, xnet_packet_t *packet)
{
    static uint32_t ip_packet_id = 0; // 用于生成IP数据包标识符
    xip_hdr_t *iphdr;

    add_header(packet, sizeof(xip_hdr_t));                                        // 为数据包添加IP头部
    iphdr = (xip_hdr_t *)packet->data;                                            // 获取IP头部
    iphdr->version = XNET_VERSION_IPV4;                                           // 设置IP版本号
    iphdr->hdr_len = sizeof(xip_hdr_t) / 4;                                       // 设置IP头部长度
    iphdr->tos = 0;                                                               // 设置服务类型
    iphdr->total_len = swap_order16(packet->size);                                // 设置IP数据包总长度
    iphdr->id = swap_order16(ip_packet_id);                                       // 设置IP数据包标识符
    iphdr->flags_fragment = 0;                                                    // 设置IP数据包标志和片偏移量
    iphdr->ttl = XNET_IP_DEFAULT_TTL;                                             // 设置IP数据包生存时间
    iphdr->protocol = protocol;                                                   // 设置上层协议类型
    memcpy(iphdr->dest_ip, dest_ip->array, XNET_IPV4_ADDR_SIZE);                  // 设置目标IP地址
    memcpy(iphdr->src_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);               // 设置源IP地址
    iphdr->hdr_checksum = 0;                                                      // 清零校验和
    iphdr->hdr_checksum = checksum16((uint16_t *)iphdr, sizeof(xip_hdr_t), 0, 1); // 计算并设置IP头部校验和

    ip_packet_id++;                       // 增加IP数据包标识符
    return ethernet_out(dest_ip, packet); // 通过以太网发送IP数据包
}

/**
 * icmp初始化
 */
void xicmp_init(void) {}

/**
 * 发送ICMP ECHO响应，即回应ping
 * @param icmp_hdr 收到的icmp包头
 * @param src_ip 包的来源ip
 * @param packet 收到的数据包
 * @return 处理结果
 */
static xnet_err_t reply_icmp_request(xicmp_hdr_t *icmp_hdr, xipaddr_t *src_ip, xnet_packet_t *packet)
{
    xicmp_hdr_t *replay_hdr;
    xnet_packet_t *tx = xnet_alloc_for_send(packet->size); // 申请一个新数据包用于发送回显响应

    replay_hdr = (xicmp_hdr_t *)tx->data; // 获取回显响应头部

    // 设置回显响应头部
    replay_hdr->type = XICMP_CODE_ECHO_REPLY; // 设置ICMP类型为回显响应
    replay_hdr->code = 0;                     // 设置ICMP代码
    replay_hdr->id = icmp_hdr->id;            // 设置ICMP标识符
    replay_hdr->seq = icmp_hdr->seq;          // 设置ICMP序号
    replay_hdr->checksum = 0;                 // 清零校验和

    // 复制原始数据
    memcpy(((uint8_t *)replay_hdr) + sizeof(xicmp_hdr_t), ((uint8_t *)icmp_hdr) + sizeof(xicmp_hdr_t), packet->size - sizeof(xicmp_hdr_t));

    // 计算并设置ICMP校验和
    replay_hdr->checksum = checksum16((uint16_t *)replay_hdr, tx->size, 0, 1);

    // 通过IP层发送ICMP响应
    return xip_out(XNET_PROTOCOL_ICMP, src_ip, tx);
}

/**
 * ICMP包输入处理
 * @param src_ip 数据包来源
 * @param packet 待处理的数据包
 */
void xicmp_in(xipaddr_t *src_ip, xnet_packet_t *packet)
{
    xicmp_hdr_t *icmphdr = (xicmp_hdr_t *)packet->data; // 获取ICMP头部

    if ((packet->size >= sizeof(xicmp_hdr_t)) && (icmphdr->type == XICMP_CODE_ECHO_REQUEST)) // 如果是ICMP回显请求
    {
        reply_icmp_request(icmphdr, src_ip, packet); // 发送ICMP回显响应
    }
}

/**
 * 发送ICMP端口不可达或协议不可达的响应
 * @param code 不可达的类型码
 * @param ip_hdr 收到的ip包
 * @return 处理结果
 */
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t *ip_hdr)
{
    xicmp_hdr_t *icmp_hdr;
    xipaddr_t dest_ip;
    xnet_packet_t *packet;

    // 计算要拷贝的ip数据量
    uint16_t ip_hdr_size = ip_hdr->hdr_len * 4;
    uint16_t ip_data_size = swap_order16(ip_hdr->total_len) - ip_hdr_size;

    // RFC文档里写的是8字节。但实际测试windows上发现复制了不止8个字节
    ip_data_size = ip_hdr_size + min(ip_data_size, 8);

    // 生成数据包，然后发送
    packet = xnet_alloc_for_send(ip_data_size + sizeof(xicmp_hdr_t));          // 分配数据包
    icmp_hdr = (xicmp_hdr_t *)packet->data;                                    // 获取ICMP头部
    icmp_hdr->type = XICMP_TYPE_UNREACH;                                       // 设置ICMP类型为不可达
    icmp_hdr->code = code;                                                     // 设置ICMP代码
    icmp_hdr->checksum = 0;                                                    // 清零校验和
    icmp_hdr->id = icmp_hdr->seq = 0;                                          // 设置ICMP标识符和序号
    memcpy(((uint8_t *)icmp_hdr) + sizeof(xicmp_hdr_t), ip_hdr, ip_data_size); // 复制IP头部和部分数据
    icmp_hdr->checksum = 0;                                                    // 清零校验和
    icmp_hdr->checksum = checksum16((uint16_t *)icmp_hdr, packet->size, 0, 1); // 计算并设置ICMP校验和
    xipaddr_from_buf(&dest_ip, ip_hdr->src_ip);                                // 获取源IP地址
    return xip_out(XNET_PROTOCOL_ICMP, &dest_ip, packet);                      // 发送ICMP不可达报文
}

/**
 * 协议栈的初始化
 */
void xnet_init(void)
{
    ethernet_init(); // 初始化以太网
    xarp_init();     // 初始化ARP
    xip_init();      // 初始化IP层
    xicmp_init();    // 初始化ICMP
}

/**
 * 轮询处理数据包，并在协议栈中处理
 */
void xnet_poll(void)
{
    ethernet_poll(); // 轮询以太网数据包
    xarp_poll();     // 轮询ARP表项
}
