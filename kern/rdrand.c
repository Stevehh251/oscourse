#include <inc/types.h>
#include "kern/rdrand.h"


unsigned check_rdrand_available(void){
    uint32_t result = 0;

    asm volatile (
        "movl $7, %%eax\n\t"    // Установка EAX в 7
        "movl $0, %%ecx\n\t"    // Установка ECX в 0
        "cpuid\n\t"             // Вызов инструкции CPUID
        "shrl $18, %%ebx\n\t"   // Сдвиг вправо на 18 бит, результат в EBX
        : "=b" (result)         // Выходной операнд, результат сохраняется в переменной result
        :                        // Нет операндов ввода
        : "%eax", "%ecx"        // Регистры, используемые в инструкции
    );

    return result;
}


unsigned rdrand(void){
    unsigned number = 0;
    
    if(!check_rdrand_available()){
        return 0;
    }

    asm volatile (
        "1: rdseed %0\n\tjnc 1b"            
        : "=r" (number)     
        :                   
        : "cc"              
    );

    return number;
}

