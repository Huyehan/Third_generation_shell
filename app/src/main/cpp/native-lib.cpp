#include <jni.h>
#include <string>
#include <android/log.h>
#include <zconf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include "libdex/DexClass.h"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "LOG_TAG", __VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_instruction_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());

}

void* get_module_base(pid_t pid,const char* module_name){
    FILE *fp;
    long addr=0;
    char *pch;
    char filename[32];
    char line[1024];
    if (pid<0){
        snprintf(filename,sizeof(filename),"/proc/self/maps",pid);
    } else{
        snprintf(filename,sizeof(filename),"/proc/%d/maps",pid);
    }
    fp=fopen(filename,"r");
    if (fp != NULL){
        while (fgets(line,sizeof(line),fp)){
//            LOGD("%s",line);
            if (strstr(line,module_name) && strstr(line, "com.example.instruction")){
                pch=strtok(line,"-");
                addr=strtoul(pch,NULL,16);
                break;
            }
        }
        fclose(fp);

    }
    return (void *)addr;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_instruction_MainActivity_chgMethod(JNIEnv *env, jobject thiz) {
    u1 *pDex= (u1 *)(get_module_base(getpid(), "classes.dex"));
    if (pDex!=NULL){
        LOGD("Get Module...");
        pDex+=sizeof(DexOptHeader);
        // 解析DEX文件
        DexFile *pDexFile=dexFileParse(pDex,sizeof(DexHeader),kDexParseContinueOnError);
        if (pDexFile==NULL){
            LOGD("unable to parse DEX");
            return;
        }
        const DexClassDef *pClassDef;
        for (int i=0;i<pDexFile->pHeader->classDefsSize;i++){
            const DexClassDef *pDef=dexGetClassDef(pDexFile,i);
            // 通过类名找到对应的DexClassDef结构体
            if (strcmp(dexStringByTypeIdx(pDexFile,pDef->classIdx),"Lcom/example/instruction/Test;")==0){
                pClassDef=pDef;
                break;
            }
        }
        if (pClassDef!=NULL){
            LOGD("Class found!!!");
            const u1 *pData=dexGetClassData(pDexFile,pClassDef);
            if (pData) {
                // 获取DexClassData结构体
                DexClassData *pClassData=dexReadAndVerifyClassData(&pData, NULL);
                for (int i=0;i<pClassData->header.virtualMethodsSize;i++){
                    DexMethod *pMethod=&pClassData->virtualMethods[i];
                    const DexMethodId *pMethodId=dexGetMethodId(pDexFile,pMethod->methodIdx);
                    // 根据方法名找到对应的DexMethod结构体
                    if (strcmp(dexStringById(pDexFile,pMethodId->nameIdx),"getNum")==0){
                        DexCode *pCode= (DexCode *)(dexGetCode(pDexFile, pMethod));
                        LOGD("Method found!!!");
                        long start_addr= (long) (pDexFile->baseAddr + pMethod->codeOff);
                        start_addr=start_addr-(start_addr%PAGE_SIZE);
                        // 修改指令所在的内存区域为可读可写
                        if (mprotect((void *)start_addr,PAGE_SIZE,
                                PROT_READ|PROT_WRITE)==0){
                            u2 new_ins[2]={0x1012,0x000f};
                            // 指令还原
                            memcpy(pCode->insns,&new_ins,2*sizeof(u2));
                            LOGD("memory reverse");
                            // 修改指令所在内存区域为可读
                            mprotect((void *)start_addr,PAGE_SIZE,PROT_READ);
                        }
                    }
                }
            }
        }
    }
}
