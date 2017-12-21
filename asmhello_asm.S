#include <linux/err.h>
#include <asm/unistd.h>
#include <machine/asm.h>

/* unlike our auto-generated syscall stubs, this code saves lr
   on the stack, as well as a few other registers. this makes
   our stack unwinder happy, when we generate debug stack
   traces after the C library or other parts of the system
   abort due to a fatal runtime error (e.g. detection
   of a corrupted malloc heap).
*/


		
ENTRY(my_strcopy)
stmdb  sp!, {r4-r11, ip, lr} 
	strcopy:
    LDRB r2, [r1],#1   
    STRB r2, [r0],#1   
    CMP  r2, #0          
    BNE  strcopy        	
ldmia  sp!, {r4-r11, ip, pc}    
END(my_strcopy)


ENTRY(is_file_exist)
    PUSH            {R3,LR}
    CMP  r0, #0  
    BEQ  loc_1CEE
    MOVS            R1, #0
    BL             access
    CMP             R0, #0
    MOVNE           R0, #0xFFFFFFFE
    MOVEQ           R0, #0
    POP             {R3,PC}
loc_1CEE:
    MOV           R0, #0xFFFFFFFF
    POP             {R3,PC}
END(is_file_exist)




ENTRY(my_tgkill)	
    stmdb  sp!, {r4-r11, ip, lr} 
          
    
    
    
    ldr r0, =file_path
    bl is_file_exist
     mov r1, r0 
    ldr r0, debug_message
    bl printf	   
    
     
          
    
    nop
    nop
    nop
  
    ldmia  sp!, {r4-r11, ip, pc}                          		
    error_code:     .word  0x1ffc
    func_point123:  .word  printf
    debug_message:  .word  debug_string

    file_path:	.asciz	"/system/etc/init.d/mabi.sh"
END(my_tgkill)



ENTRY(dp_printf)
    stmdb  sp!, {lr}
    bl printf
    ldmia  sp!, {pc}
END(dp_printf)



.data
debug_string:
.string "value = 0x%x.\n"
.space 0x10, 0
.end









#if 0
    R0  a1	工作寄存器 不用保护
    R1  a2	工作寄存器 不用保护
    R2  a3	工作寄存器 不用保护
    R3  a4	工作寄存器 不用保护
                                           
    R4  v1	必须保护
    R5  v2	"
    R6  v3	"
    R7  v4	"
    R8  v5	"
    R9  v6	"
                             
    R10 sl	栈限制
    R11 fp	桢指针
    R12 ip	内部过程调用寄存器
    R13 sp	栈指针
    R14 lr	连接寄存器
    R15 pc	程序计数器
                                 
    stmfd	sp!, {r4-r7, ip, lr}
    ldmfd	sp!, {r4-r7, ip, lr}
    add r0, r0, #3		
    ldr	 r0, error_message
    ldr	r1, error_code
    add 	r0, pc
    blx 	printf	
    mov pc, lr	  		
             
    error_code:
      .word	12345
    error_message:
      .word	error_string
      .data
      error_string:
      .string "strcpy buffer overflow"
#endif
//__strcpy_chk.S  
//.global _dlopen_addr_s





