#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define SOURCE_FILE "/tmp/source.txt"
#define DEST_FILE "/tmp/dest.txt"
#define BUFFER_SIZE 8192  // Larger buffer size for better performance

static int __init file_copy_init(void)
{
    struct file *src_file, *dest_file;
    char *buffer;
    mm_segment_t old_fs;
    ssize_t bytes_read, bytes_written;

    printk(KERN_INFO "File Copy Module Initialized\n");

    buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory\n");
        return -ENOMEM;
    }

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    src_file = filp_open(SOURCE_FILE, O_RDONLY, 0);
    if (IS_ERR(src_file)) {
        printk(KERN_ERR "Failed to open source file\n");
        kfree(buffer);
        set_fs(old_fs);
        return PTR_ERR(src_file);
    }

    dest_file = filp_open(DEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(dest_file)) {
        printk(KERN_ERR "Failed to open destination file\n");
        filp_close(src_file, NULL);
        kfree(buffer);
        set_fs(old_fs);
        return PTR_ERR(dest_file);
    }

    while ((bytes_read = kernel_read(src_file, buffer, BUFFER_SIZE, &src_file->f_pos)) > 0) {
        bytes_written = kernel_write(dest_file, buffer, bytes_read, &dest_file->f_pos);
        if (bytes_written < 0) {
            printk(KERN_ERR "Failed to write to destination file\n");
            break;
        }
    }

    filp_close(src_file, NULL);
    filp_close(dest_file, NULL);
    kfree(buffer);
    set_fs(old_fs);

    printk(KERN_INFO "File copy completed\n");
    return 0;
}

static void __exit file_copy_exit(void)
{
    printk(KERN_INFO "File Copy Module Exited\n");
}

module_init(file_copy_init);
module_exit(file_copy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A Simple Kernel Module to Copy File Content");

'''
// kernel module for hardidsk partition and filesystem

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/partitions.h>
#include <linux/bio.h>
#include <linux/mount.h>

#define DEVICE_NAME "/dev/sdb" // Replace with your external device
#define PARTITION_SIZE 1024 * 1024 * 1024 // 1 GB

static int __init partition_and_format_init(void)
{
    struct block_device *bdev;
    struct hd_struct *part;
    int ret;

    printk(KERN_INFO "Partition and Format Module Initialized\n");

    bdev = blkdev_get_by_path(DEVICE_NAME, FMODE_WRITE, NULL);
    if (IS_ERR(bdev)) {
        printk(KERN_ERR "Failed to open device\n");
        return PTR_ERR(bdev);
    }

    // Example: partitioning and formatting code
    // You need to implement partitioning and filesystem creation here

    // Cleanup
    blkdev_put(bdev, FMODE_WRITE);
    printk(KERN_INFO "Partition and Format Completed\n");
    return 0;
}

static void __exit partition_and_format_exit(void)
{
    printk(KERN_INFO "Partition and Format Module Exited\n");
}

module_init(partition_and_format_init);
module_exit(partition_and_format_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Module to Partition and Format External Disk");


// user space version

#include <stdio.h>
#include <stdlib.h>
#include <parted/parted.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define DEVICE_NAME "/dev/sdb" // Replace with your external device
#define PARTITION_SIZE 1024 * 1024 * 1024 // 1 GB

void partition_and_format(const char *device) {
    PedDevice *dev;
    PedDisk *disk;
    PedPartition *part;
    PedPartitionType *type;
    PedGeometry *geom;

    // Initialize libparted
    ped_device_probe_all();

    // Open the device
    dev = ped_device_get(device);
    if (!dev) {
        perror("ped_device_get");
        exit(EXIT_FAILURE);
    }

    // Open the disk
    disk = ped_disk_new(dev);
    if (!disk) {
        perror("ped_disk_new");
        ped_device_destroy(dev);
        exit(EXIT_FAILURE);
    }

    // Create a new partition
    geom = ped_geometry_new(dev, 0, PARTITION_SIZE);
    type = ped_partition_type_get("ext4");
    if (!type) {
        fprintf(stderr, "Failed to get partition type\n");
        ped_disk_destroy(disk);
        ped_device_destroy(dev);
        exit(EXIT_FAILURE);
    }

    part = ped_partition_new(disk, type, geom->start, geom->end);
    if (!part) {
        fprintf(stderr, "Failed to create partition\n");
        ped_disk_destroy(disk);
        ped_device_destroy(dev);
        exit(EXIT_FAILURE);
    }

    // Commit changes
    if (!ped_disk_commit(disk)) {
        fprintf(stderr, "Failed to commit changes\n");
        ped_disk_destroy(disk);
        ped_device_destroy(dev);
        exit(EXIT_FAILURE);
    }

    printf("Partition created successfully\n");

    // Format the partition
    char command[256];
    snprintf(command, sizeof(command), "mkfs.ext4 %s1", device);
    if (system(command) != 0) {
        perror("system");
        ped_disk_destroy(disk);
        ped_device_destroy(dev);
        exit(EXIT_FAILURE);
    }

    printf("Partition formatted successfully\n");

    // Cleanup
    ped_disk_destroy(disk);
    ped_device_destroy(dev);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <device>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *device = argv[1];
    partition_and_format(device);

    return 0;
}

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/cdev.h>

#define DEVICE_NAME "netmod_device"
#define BUFFER_SIZE 1024

static int major;
static struct cdev netmod_cdev;
static char device_buffer[BUFFER_SIZE];

static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
    ssize_t ret = simple_read_from_buffer(buffer, len, offset, device_buffer, strlen(device_buffer));
    return ret;
}

static ssize_t device_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    ssize_t ret = simple_write_to_buffer(device_buffer, BUFFER_SIZE, offset, buffer, len);
    return ret;
}

static int device_open(struct inode *inode, struct file *file) {
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
};

static int __init netmod_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "Registering char device failed with %d\n", major);
        return major;
    }
    printk(KERN_INFO "Registered character device with major number %d\n", major);
    return 0;
}

static void __exit netmod_exit(void) {
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Unregistered character device\n");
}

module_init(netmod_init);
module_exit(netmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Module with Character Device Interface");


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Network module with Wi-Fi and Ethernet modes, MAC and IP management");

static char *mode = "ether"; // "wifi" or "ether"
module_param(mode, charp, 0644);
MODULE_PARM_DESC(mode, "Network mode: 'wifi' or 'ether'");

static struct net_device *target_dev;
static char *blacklist_ip = NULL;
module_param(blacklist_ip, charp, 0644);
MODULE_PARM_DESC(blacklist_ip, "IP address to blacklist");

static void set_mac_address(struct net_device *dev, const char *new_mac) {
    struct sockaddr sa;
    int err;

    sscanf(new_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &((struct sockaddr_dl *)&sa)->sdl_data[0],
           &((struct sockaddr_dl *)&sa)->sdl_data[1],
           &((struct sockaddr_dl *)&sa)->sdl_data[2],
           &((struct sockaddr_dl *)&sa)->sdl_data[3],
           &((struct sockaddr_dl *)&sa)->sdl_data[4],
           &((struct sockaddr_dl *)&sa)->sdl_data[5]);

    dev->set_mac_address(&sa);
}

static int filter_ip_address(const struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    char src_ip[16];

    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);

    if (blacklist_ip && strcmp(src_ip, blacklist_ip) == 0) {
        return 1; // Drop packet
    }

    return 0; // Allow packet
}

static rx_handler_result_t process_packet(struct sk_buff **pskb) {
    if (filter_ip_address(*pskb)) {
        kfree_skb(*pskb);
        return RX_HANDLER_CONSUMED;
    }

    return RX_HANDLER_PASS;
}

static int __init netmod_init(void) {
    target_dev = dev_get_by_name(&init_net, "eth0"); // or "wlan0" for Wi-Fi
    if (!target_dev) {
        pr_err("Failed to get target device\n");
        return -ENODEV;
    }

    if (strcmp(mode, "wifi") == 0) {
        // Initialize Wi-Fi mode
    } else {
        // Initialize Ethernet mode
    }

    // Set up packet filtering
    struct net_device *dev = target_dev;
    struct net_device *dev_rx_handler = dev;
    dev_add_pack(&netmod_packet_type);

    return 0;
}

static void __exit netmod_exit(void) {
    dev_remove_pack(&netmod_packet_type);
    if (target_dev) {
        dev_put(target_dev);
    }
}

module_init(netmod_init);
module_exit(netmod_exit);


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Enhanced Network Module for Multiple Interfaces with MAC and IP management");

static char *mode = "ether"; // "wifi" or "ether"
module_param(mode, charp, 0644);
MODULE_PARM_DESC(mode, "Network mode: 'wifi' or 'ether'");

static char *blacklist_ip = NULL;
module_param(blacklist_ip, charp, 0644);
MODULE_PARM_DESC(blacklist_ip, "IP address to blacklist");

static LIST_HEAD(interface_list);
static DEFINE_MUTEX(interface_list_lock);

struct interface_info {
    struct net_device *dev;
    struct list_head list;
};

static void set_mac_address(struct net_device *dev, const char *new_mac) {
    struct sockaddr sa;
    int err;

    sscanf(new_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &((struct sockaddr_dl *)&sa)->sdl_data[0],
           &((struct sockaddr_dl *)&sa)->sdl_data[1],
           &((struct sockaddr_dl *)&sa)->sdl_data[2],
           &((struct sockaddr_dl *)&sa)->sdl_data[3],
           &((struct sockaddr_dl *)&sa)->sdl_data[4],
           &((struct sockaddr_dl *)&sa)->sdl_data[5]);

    dev->set_mac_address(&sa);
}

static int filter_ip_address(const struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    char src_ip[16];

    snprintf(src_ip, sizeof(src_ip), "%pI4", &iph->saddr);

    if (blacklist_ip && strcmp(src_ip, blacklist_ip) == 0) {
        return 1; // Drop packet
    }

    return 0; // Allow packet
}

static rx_handler_result_t process_packet(struct sk_buff **pskb) {
    if (filter_ip_address(*pskb)) {
        kfree_skb(*pskb);
        return RX_HANDLER_CONSUMED;
    }

    return RX_HANDLER_PASS;
}

static void add_interface(const char *ifname) {
    struct net_device *dev = dev_get_by_name(&init_net, ifname);
    if (!dev) {
        pr_err("Failed to get device %s\n", ifname);
        return;
    }

    struct interface_info *info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info) {
        pr_err("Failed to allocate memory for interface info\n");
        dev_put(dev);
        return;
    }

    info->dev = dev;
    INIT_LIST_HEAD(&info->list);

    mutex_lock(&interface_list_lock);
    list_add_tail(&info->list, &interface_list);
    mutex_unlock(&interface_list_lock);

    dev_add_pack(&netmod_packet_type);
}

static void remove_interface(const char *ifname) {
    struct interface_info *info, *tmp;

    mutex_lock(&interface_list_lock);
    list_for_each_entry_safe(info, tmp, &interface_list, list) {
        if (strcmp(info->dev->name, ifname) == 0) {
            dev_remove_pack(&netmod_packet_type);
            list_del(&info->list);
            dev_put(info->dev);
            kfree(info);
            break;
        }
    }
    mutex_unlock(&interface_list_lock);
}

static int __init netmod_init(void) {
    if (strcmp(mode, "wifi") == 0) {
        // Initialize Wi-Fi mode
    } else {
        // Initialize Ethernet mode
    }

    // Add initial interfaces
    add_interface("eth0");
    add_interface("wlan0");

    return 0;
}

static void __exit netmod_exit(void) {
    struct interface_info *info, *tmp;

    mutex_lock(&interface_list_lock);
    list_for_each_entry_safe(info, tmp, &interface_list, list) {
        dev_remove_pack(&netmod_packet_type);
        list_del(&info->list);
        dev_put(info->dev);
        kfree(info);
    }
    mutex_unlock(&interface_list_lock);
}

module_init(netmod_init);
module_exit(netmod_exit);
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/cdev.h>

#define DEVICE_NAME "netmod_device"
#define BUFFER_SIZE 1024

static int major;
static struct cdev netmod_cdev;
static char device_buffer[BUFFER_SIZE];

static ssize_t device_read(struct file *file, char __user *buffer, size_t len, loff_t *offset) {
    ssize_t ret = simple_read_from_buffer(buffer, len, offset, device_buffer, strlen(device_buffer));
    return ret;
}

static ssize_t device_write(struct file *file, const char __user *buffer, size_t len, loff_t *offset) {
    ssize_t ret = simple_write_to_buffer(device_buffer, BUFFER_SIZE, offset, buffer, len);
    return ret;
}

static int device_open(struct inode *inode, struct file *file) {
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
};

static int __init netmod_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "Registering char device failed with %d\n", major);
        return major;
    }
    printk(KERN_INFO "Registered character device with major number %d\n", major);
    return 0;
}

static void __exit netmod_exit(void) {
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "Unregistered character device\n");
}

module_init(netmod_init);
module_exit(netmod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel Module with Character Device Interface");




#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/slab.h>

#define MODULE_NAME "packet_filter"

static struct nf_hook_ops nfho;

static unsigned int packet_filter_hook(void *priv,
                                       struct sk_buff *skb,
                                       const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    ktime_t timestamp;
    struct timeval tv;
    
    // Check if skb is valid
    if (!skb)
        return NF_ACCEPT;

    // Extract IP header
    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // Extract TCP header if protocol is TCP
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (tcph) {
            // Get current time
            timestamp = ktime_get_real();
            do_gettimeofday(&tv);
            printk(KERN_INFO "[%s] Packet from %pI4 to %pI4, Timestamp: %lu.%06lu\n",
                   MODULE_NAME,
                   &iph->saddr,
                   &iph->daddr,
                   tv.tv_sec,
                   tv.tv_usec);

            // Check for common TCP flags
            if (tcph->syn)
                printk(KERN_INFO "[%s] SYN flag set\n", MODULE_NAME);
            if (tcph->ack)
                printk(KERN_INFO "[%s] ACK flag set\n", MODULE_NAME);
            if (tcph->fin)
                printk(KERN_INFO "[%s] FIN flag set\n", MODULE_NAME);
            if (tcph->rst)
                printk(KERN_INFO "[%s] RST flag set\n", MODULE_NAME);
        }
    }
    
    return NF_ACCEPT; // Accept the packet
}

static int __init packet_filter_init(void) {
    nfho.hook = packet_filter_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    // Register the hook
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "%s module loaded\n", MODULE_NAME);
    return 0;
}

static void __exit packet_filter_exit(void) {
    // Unregister the hook
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "%s module unloaded\n", MODULE_NAME);
}

module_init(packet_filter_init);
module_exit(packet_filter_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple packet filter kernel module");


#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

static unsigned int my_hook_fn(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // Example: Check TCP packets
    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        // Logic to detect new connections
        // For example, check for SYN flag
        if (tcph->syn && !tcph->ack) {
            printk(KERN_INFO "New TCP connection detected: %pI4\n", &iph->saddr);
            // Call your packet filter module here
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops my_nfho = {
    .hook = my_hook_fn,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init my_module_init(void) {
    nf_register_hook(&my_nfho);
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_hook(&my_nfho);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

void start_daemon() {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);  // Parent exits
    }

    // Child process
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    umask(0);
    chdir("/");

    // Close file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    while (1) {
        // Load the kernel module
        system("modprobe my_module");

        // Implement logic to monitor and handle connections
        // ...

        sleep(60);  // Sleep for a while
    }
}

int main() {
    start_daemon();
    return 0;
}


#######3
ICMP Echo 


#include <linux/net.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/icmp.h>

void send_icmp_echo_request(struct in_addr dest_addr) {
    struct sockaddr_in addr;
    struct icmphdr icmp_hdr;
    struct msghdr msg;
    struct iovec iov;
    int sockfd;

    // Create a socket
    sockfd = sock_create_kern(AF_INET, SOCK_RAW, IPPROTO_ICMP, &sockfd);
    if (sockfd < 0) {
        printk(KERN_ERR "Failed to create socket\n");
        return;
    }

    // Prepare the ICMP header
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = htons(1);
    icmp_hdr.un.echo.sequence = htons(1);

    // Set up the message
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &icmp_hdr;
    iov.iov_len = sizeof(icmp_hdr);
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    addr.sin_family = AF_INET;
    addr.sin_addr = dest_addr;

    // Send the ICMP packet
    if (sock_sendmsg(sockfd, &msg) < 0) {
        printk(KERN_ERR "Failed to send ICMP packet\n");
    }

    sock_release(sockfd);
}


#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

static unsigned int my_packet_filter(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (iph->protocol == IPPROTO_ICMP) {
        icmph = icmp_hdr(skb);
        if (icmph->type == ICMP_ECHO) {
            // Handle ICMP Echo Requests here
            printk(KERN_INFO "ICMP Echo Request from %pI4\n", &iph->saddr);
        }
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = my_packet_filter,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init my_module_init(void) {
    nf_register_hook(&nfho);
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_hook(&nfho);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");



#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/module.h>
#include <linux/kernel.h>

static unsigned int my_packet_filter(void *priv,
                                      struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    unsigned int protocol;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    protocol = iph->protocol;

    switch (protocol) {
        case IPPROTO_TCP:
            tcph = tcp_hdr(skb);
            printk(KERN_INFO "TCP Packet: Source Port: %u, Dest Port: %u\n",
                   ntohs(tcph->source), ntohs(tcph->dest));
            break;
        case IPPROTO_UDP:
            udph = udp_hdr(skb);
            printk(KERN_INFO "UDP Packet: Source Port: %u, Dest Port: %u\n",
                   ntohs(udph->source), ntohs(udph->dest));
            break;
        case IPPROTO_ICMP:
            icmph = icmp_hdr(skb);
            printk(KERN_INFO "ICMP Packet: Type: %u, Code: %u\n",
                   icmph->type, icmph->code);
            break;
        default:
            printk(KERN_INFO "Other Protocol: %u\n", protocol);
            break;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = my_packet_filter,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init my_module_init(void) {
    nf_register_hook(&nfho);
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_hook(&nfho);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");


#############################
# KERNEL NET PACKET CAPTURE #

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>

#define NETLINK_USER 31

static struct sock *nl_sk = NULL;

static unsigned int packet_filter(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        // Example: Notify user space of detected TCP packets
        struct sk_buff *skb_out;
        struct nlmsghdr *nlh;
        int msg_size;
        char *msg = "TCP Packet Detected";

        msg_size = strlen(msg);
        skb_out = nlmsg_new(msg_size, 0);

        if (!skb_out) {
            printk(KERN_ERR "Failed to allocate new skb\n");
            return NF_ACCEPT;
        }

        nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
        memcpy(nlmsg_data(nlh), msg, msg_size);

        nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
        if (!nl_sk) {
            printk(KERN_ERR "Failed to create netlink socket\n");
            kfree_skb(skb_out);
            return NF_ACCEPT;
        }

        netlink_unicast(nl_sk, skb_out, 0, MSG_DONTWAIT);
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = packet_filter,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init my_module_init(void) {
    nf_register_hook(&nfho);
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_hook(&nfho);
    if (nl_sk)
        netlink_kernel_release(nl_sk);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/slab.h>

#define MAX_IP_ENTRIES 1024

static struct net_device *dev;
static spinlock_t ip_list_lock;
static struct hlist_head *ip_list;

struct ip_entry {
    __be32 ip;
    struct hlist_node node;
};

static int process_packet(struct sk_buff *skb) {
    struct iphdr *ip_header;
    struct ip_entry *entry;

    // Get IP header
    ip_header = ip_hdr(skb);

    // Lock for safe access to the IP list
    spin_lock(&ip_list_lock);

    // Check if IP is in the list
    hlist_for_each_entry(entry, &ip_list[ip_header->daddr % MAX_IP_ENTRIES], node) {
        if (entry->ip == ip_header->daddr) {
            // IP found
            spin_unlock(&ip_list_lock);
            return 0;
        }
    }

    // Add new IP entry to the list
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        spin_unlock(&ip_list_lock);
        return -ENOMEM;
    }
    entry->ip = ip_header->daddr;
    hlist_add_head(&entry->node, &ip_list[ip_header->daddr % MAX_IP_ENTRIES]);

    // Unlock after modification
    spin_unlock(&ip_list_lock);

    return 0;
}

static int __init my_module_init(void) {
    int i;

    // Initialize IP list and lock
    ip_list = kmalloc_array(MAX_IP_ENTRIES, sizeof(struct hlist_head), GFP_KERNEL);
    if (!ip_list)
        return -ENOMEM;
    for (i = 0; i < MAX_IP_ENTRIES; i++)
        INIT_HLIST_HEAD(&ip_list[i]);
    spin_lock_init(&ip_list_lock);

    // Register network device hook
    dev = dev_get_by_name(&init_net, "eth0");
    if (!dev)
        return -ENODEV;

    // Hooking code here...

    return 0;
}

static void __exit my_module_exit(void) {
    // Cleanup code here
    kfree(ip_list);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Optimized Network Module");
MODULE_AUTHOR("Your Name");


#############
# USER MODE #

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <arpa/inet.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

static int netlink_fd;

void receive_messages() {
    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct msghdr msg;
    struct iovec iov;
    char buffer[MAX_PAYLOAD];

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (netlink_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (bind(netlink_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(netlink_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        memset(buffer, 0, MAX_PAYLOAD);
        iov.iov_base = buffer;
        iov.iov_len = MAX_PAYLOAD;
        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(sa);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        ssize_t len = recvmsg(netlink_fd, &msg, 0);
        if (len < 0) {
            perror("recvmsg");
            continue;
        }

        nlh = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(nlh, len)) {
            printf("Received message: %s\n", (char *)NLMSG_DATA(nlh));
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
}

int main() {
    receive_messages();
    close(netlink_fd);
    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <errno.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

static int netlink_fd;

void handle_message(struct nlmsghdr *nlh) {
    printf("Received message: %s\n", (char *)NLMSG_DATA(nlh));
}

void receive_messages() {
    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct msghdr msg;
    struct iovec iov;
    char buffer[MAX_PAYLOAD];
    ssize_t len;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    netlink_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (netlink_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (bind(netlink_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(netlink_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        memset(buffer, 0, MAX_PAYLOAD);
        iov.iov_base = buffer;
        iov.iov_len = MAX_PAYLOAD;
        msg.msg_name = &sa;
        msg.msg_namelen = sizeof(sa);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        msg.msg_flags = 0;

        len = recvmsg(netlink_fd, &msg, 0);
        if (len < 0) {
            perror("recvmsg");
            continue;
        }

        nlh = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(nlh, len)) {
            handle_message(nlh);
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
}

int main() {
    receive_messages();
    close(netlink_fd);
    return 0;
}




****************
* WIFI 

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/sock.h>

// Callback function for netlink events
static void netlink_callback(struct sk_buff *skb, void *data) {
    // Parse and handle the netlink message to detect interface changes
    // Check if the Wi-Fi interface has been connected or disconnected
}

// Initialize netlink socket
void setup_netlink() {
    struct socket *sock;
    struct sockaddr_nl addr;

    sock_create_kern(&init_net, PF_NETLINK, SOCK_RAW, NETLINK_ROUTE, &sock);
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK; // Listen to link changes
    sock->ops->bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    sock->ops->recvmsg(sock, skb, 0);
}

// Function to get the ARP table
void get_arp_table() {
    // Use kernel APIs to access ARP table entries
    // Parse the ARP table to find connected IP addresses
}

#include <linux/netlink.h>
#include <linux/socket.h>

#define NETLINK_USER 31

static struct sock *nl_sk = NULL;

void send_ip_to_userspace(const char *ip) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = strlen(ip) + 1;
    int res;

    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "Failed to allocate new netlink message\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    strncpy(nlmsg_data(nlh), ip, msg_size);

    res = nlmsg_unicast(nl_sk, skb, 0);
    if (res < 0) {
        printk(KERN_INFO "Error while sending netlink message: %d\n", res);
    }
}

static void netlink_recv_msg(struct sk_buff *skb) {
    // Handle messages received from user space
}

void init_netlink() {
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "Error creating netlink socket\n");
    }
}

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/buffer_head.h>
#include <linux/workqueue.h>
#include <linux/string.h>

#define MAX_FILES 100
#define BUFFER_SIZE 1024

static char *file_buffer;
static struct workqueue_struct *search_wq;
static struct work_struct search_work;

typedef struct {
    char *file_path;
    char *search_pattern;
} search_task_t;

static void process_search_work(struct work_struct *work) {
    search_task_t *task = container_of(work, search_task_t, work);
    struct file *file;
    struct inode *inode;
    loff_t pos = 0;
    ssize_t bytes_read;
    char *buf;
    
    file = filp_open(task->file_path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open file %s\n", task->file_path);
        return;
    }
    
    inode = file->f_inode;
    buf = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate buffer\n");
        filp_close(file, NULL);
        return;
    }
    
    while ((bytes_read = kernel_read(file, buf, BUFFER_SIZE, &pos)) > 0) {
        // Process buffer for search pattern
        if (strstr(buf, task->search_pattern)) {
            printk(KERN_INFO "Pattern found in file %s\n", task->file_path);
       }
    }
    
    kfree(buf);
    filp_close(file, NULL);
}

static int __init my_module_init(void) {
    search_wq = create_workqueue("search_wq");
    if (!search_wq) {
        printk(KERN_ERR "Failed to create workqueue\n");
        return -ENOMEM;
    }
    
    // Example of adding a search task to the workqueue
    search_task_t *task = kmalloc(sizeof(search_task_t), GFP_KERNEL);
    if (!task) {
        printk(KERN_ERR "Failed to allocate search task\n");
        destroy_workqueue(search_wq);
        return -ENOMEM;
    }
    
    task->file_path = "/path/to/file";
    task->search_pattern = "pattern";
    INIT_WORK(&task->work, process_search_work);
    
    queue_work(search_wq, &task->work);
    
    return 0;
}

static void __exit my_module_exit(void) {
    flush_workqueue(search_wq);
    destroy_workqueue(search_wq);
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Enhanced kernel module for file searching");
MODULE_AUTHOR("Your Name");

'''''''''''''



