#ifndef JOS_KERN_RDRAND_H
#define JOS_KERN_RDRAND_H

unsigned check_rdrand_available(void);
unsigned rdrand(void);

#endif /* JOS_KERN_RDRAND_H */