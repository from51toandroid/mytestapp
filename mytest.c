
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/input.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <cutils/sockets.h>
#include <cutils/klog.h>
#include <android/log.h>
#include <utils/Log.h>
#include <syslog.h>
#include <netinet/in.h>



#define LOGE(x...) do { KLOG_ERROR("events", x); } while (0)
#define LOGI(x...) do { KLOG_INFO("events", x); } while (0)
#define LOGV(x...) do { KLOG_DEBUG("events", x); } while (0)


#define MAX_DEVICES 16
#define MAX_MISC_FDS 16

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(x) (((x) + BITS_PER_LONG - 1) / BITS_PER_LONG)

#define test_bit(bit, array) \
    ((array)[(bit)/BITS_PER_LONG] & (1 << ((bit) % BITS_PER_LONG)))





#if 0
    int _src;
    _src =1;
    asm volatile(
            "nop\n"
            "mov r0, r0\n"
            "mov r0, %0\n"
         :: "r" (_src) : "r0", "r1", "r2", "r3");
         //:输出:输入:破坏的寄存器
         //"r" 告诉编译器使用寄存器处理输入变量
#endif


#if 0
int get_r0_reg( void )            
{
    unsigned long old,temp; 
	temp = 3;
    __asm__ __volatile__( "adr r0, 0x444\n" 
		                  "mov %0, r0\n"  
                                : "=r" (temp) 
                                :
                                : "memory"); 
                return temp; 
				
   
    
}
#endif



	   

int main1( void )
{	


    __asm__ __volatile__( "nop\n"::: "memory"); 
	__asm__ __volatile__( "nop\n"::: ); 
	__asm__ __volatile__( "nop\n"::: "memory"); 
    printf( "hello3123.\n");
	printf( "hello123.\n");
	printf( "hello123.\n");
	printf( "hello123.\n");
    printf( "hello123.\n");
	return 5;
}


















































