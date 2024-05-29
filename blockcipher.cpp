//SM4加密算法
#include<iostream>
#include<stdio.h>
#include<math.h>
#include<time.h>
#include<stack>
#define MAX 102400
using namespace std;
//S盒结构定义
static const unsigned char SboxTable[16][16] =
{
	{0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
	{0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
	{0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
	{0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
	{0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
	{0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
	{0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
	{0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
	{0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
	{0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
	{0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
	{0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
	{0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
	{0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
	{0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
	{0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}
};

//轮密钥生成过程中需要的参数
static const unsigned long FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const unsigned long CK[32] =
{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};


//该函数输入8位数据，返回8位数据
//S盒函数
static const unsigned char S(unsigned char information)//输入一个字节数据，通过查找Sbox获取输出字节
{
    int number = information;
    int y = number % 16;
    int x = number / 16;
    return SboxTable[x][y];
}

//该函数输入32位数据，返回32位数据
unsigned long ls(unsigned long A)//非线性变换,输入样例0xab125d93
{
	unsigned char* b = new unsigned char[4];
	unsigned long B = 0;
	unsigned char a[4];
	//printf("%x\n", A);
	//将32位数据转化为4个8位数据，并存放于数组中
	a[3] = A % 256;
	a[2] = (A / 256) % 256;
	a[1] = (A / 256 / 256) % 256;
	a[0] = A / 256 / 256 / 256;
	//printf("\n");
	for (int i = 0; i < 4; i++)
	{
		b[i] = S(a[i]);//逐个计算S盒函数
	}
	for (int i = 0; i < 4; i++)
	{
		B += b[i] * (int)pow(256,3-i);//将S盒函数重新连接位一个32位数据
	}
	return B;
}

//该函数输入32位数据，返回32位数据
unsigned long LeftShift(unsigned long a,int n)//循环左移n位函数
{
	for (int i = 0; i < n;i++)
	{
		unsigned long head = (a >> 31) & 0x1;//将a向右移动31位使得第32位数据位与最低位，与0x1相与，其他位置为0，获取第32位数据
		//printf("head = %ld\n", head);
		unsigned long space = a & (~0x80000000);//将a的32位置为0，防止32位为1，long有64位之后左移会导致33位不为0
		//printf("space = %x\n", space);
		unsigned long other = (space << 1) &(~0x1); //将a向左移动1位
		//printf("other = %x\n", other);
		a = other + head;//将得到的字符串与最高位相加，则最高位连接到了最低位
	}
	return a;
}

//该函数输入32位数据，返回32位数据
unsigned long L(unsigned long B)//线性变换L
{
	unsigned long C;
	unsigned long B2 = LeftShift(B, 2);//表示B循环左移2位
	unsigned long B10 = LeftShift(B, 10);//表示B循环左移10位
	unsigned long B18 = LeftShift(B, 18);//表示B循环左移18位
	unsigned long B24 = LeftShift(B, 24);//表示循环左移24位
	C = B ^ B2 ^ B10 ^ B18 ^ B24;//逐比特异或运算
	return C;
}

//该函数输入32位数据，返回32位数据
unsigned long L1(unsigned long B)//线性变换L`
{
	unsigned long C;
	unsigned long B13 = LeftShift(B, 13);
	unsigned long B23 = LeftShift(B, 23);
	C = B ^ B13 ^ B23;
	return C;
}

//该函数输入32位数据，返回32位数据
unsigned long T(unsigned long X)//T变换
{
	unsigned long D;
	D = L(ls(X));//线性变换和非线性变换结合构成合成变换T
	return D;
}

//该函数输入32位数据，返回32位数据
unsigned long T1(unsigned long X)//T`变换
{
	unsigned long D;
	D = L1(ls(X));
	return D;
}

//该函数输入4个32位的加密密钥,返回rk数组，包含32个32位轮密钥
unsigned long* RoundKey(unsigned long* MK)//轮密钥生成函数
{
	unsigned long K[36];
	unsigned long* rk = new unsigned long[32];
	for (int i = 0; i < 4;i++)
	{
		K[i] = MK[i] ^ FK[i];
	}//生成K0，K1，K2，K3
	for (int i = 0; i < 32;i++)
	{
		rk[i] = K[i + 4] = K[i] ^ T1(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
	}
	return rk;
}

//该函数输入4个32位数据和一个32位轮密钥,返回32位数据
unsigned long F(unsigned long X0,unsigned long X1,unsigned long X2,unsigned long X3,unsigned long rk)//轮函数
{
	unsigned long D;
	D = X0 ^ T(X1 ^ X2 ^ X3 ^ rk);
	return D; // 输出的为X[i+4];
}

//输入4个32位明文数据共128比特，输入32个轮密钥输出4个32位密文
unsigned long* Encrypt(unsigned long* X,unsigned long* rk)//加密函数
{
	unsigned long *Y = new unsigned long[4];
	unsigned long data[36];
	data[0] = X[0];
	data[1] = X[1];
	data[2] = X[2];
	data[3] = X[3];
	for (int i = 0; i < 32;i++)
	{
		data[i + 4] = F(data[i], data[i + 1], data[i + 2], data[i + 3], rk[i]);
	}//32次论迭代
	//反序输出
	Y[0] = data[35];
	Y[1] = data[34];
	Y[2] = data[33];
	Y[3] = data[32];
	return Y;
}

//输入4组32位密文数据，和32个轮密钥，与加密函数轮密钥相同，但是反序
unsigned long* Decrypt(unsigned long* Y,unsigned long* rk)//解密函数
{
	unsigned long *X = new unsigned long[4];
	unsigned long data[36];
	data[35] = Y[0];
	data[34] = Y[1];
	data[33] = Y[2];
	data[32] = Y[3];
	for (int i = 31; i >= 0;i--)
	{
		data[i] = F(data[i + 4], data[i + 3], data[i + 2], data[i + 1], rk[i]);
	}
	X[0] = data[0];
	X[1] = data[1];
	X[2] = data[2];
	X[3] = data[3];
	return X;
}

//输入32数据，以二进制输出,测试用数据
void ShowB(unsigned long info,int t = 0)
{
	stack<int> s;
	int d;
	for (int i = 0; i < 32;i++)
		{
			d = (info >> i) % 2;
			s.push(d);
		}
		for (int i = 0; i < 32;i++)
		{
			cout << s.top();
			s.pop();
		}
		if(t == 0)
		{
			cout << endl;
		}
		if(t == 1)
		{
			cout << " ";
		}
}

//输入一个指针，以16进制数据输出，string参数为输出的提示信息，size表示分为多少块输出，块见换行隔开
void ShowH(unsigned long* data,const char* string,int size = 1)
{
	cout << string << endl;
	for (int i = 0; i < size;i++)
	{
		for (int j = 0; j < 4;j++)
		{
			printf("%08x ", data[i * 4 + j]);
		}
		printf("\n");
	}
}

//输4个32位初始密钥
unsigned long* inputMK()
{
	cout << "请输入128位密钥(分为四组输入每组最大32比特):";
	unsigned long *mk = new unsigned long[4];
	for (int i = 0; i < 4;i++)
	{
		cin >> mk[i];
	}
	return mk;
}

//输入需要加密的信息，可以是任何类型的信息，返回一个char*数组
unsigned char* inputinformation()
{
	cout << "请输入需要加密的信息:";
	unsigned char *information = new unsigned char[MAX];
	char *buffer = new char[MAX];
	cin.getline(buffer, MAX + 1);
	information =(unsigned char*)buffer;
	return information;
}

//输入明文信息，字长不确定(以\0结尾)，将明文以32位为基本单位，每4个为一组，构成多组128位明文，不足的明文信息使用剩余字节长度填充
unsigned long* partition(unsigned char* information,int &size)
{
	int len = 0;
	if(size == 0)//如果size为0表示在加密过程中调用此函数，则需要逐个字节读取，以"\0"表示结尾
	{
	while(information[len] != '\0')
		len++;//len表示有多少个8位有效数据块
	size = len / 16 + (len % 16 != 0 ? 1 : 0);//size表示有多少个128位有效数据块
	}
	else//如果size不为0表示在解密的时候调用此函数，则跳过计算len的过程，直接通过size的值反向计算len
	{
		len = size * 16;
	}
	int number = size*4;//number表示有多少个32位有效数据块
	int space = size * 16 - len;//记录有多少个字节为空，用于填充
	//  cout << "len::" << len << endl;
	//  cout << "size::" << size << endl;
	//  cout << "number::" << number << endl;
	//  cout << "space::" << space << endl;
	unsigned long *data = new unsigned long[number]; // 动态规划数组空间，用来存放分组明文，每四个为一组
	for (int i = 0; i < number;i++)//将data全部置为0
	{
		data[i] = 0;
	}
	int j = 0;//用来记录当前输入到数组中的32位数据个数
	for (int i = 0; i < len;i+=4)//每32个字节一循环，通过i和k一起控制
	{
		int length = (len - i >= 4) ? 4 : len - i;//判断剩余长度能否构成一个32位数据，控制是否填充信息
		for (int k = 0; k < length;k++)
		{
			data[i/4] = (data[i/4] << 8) + information[i + k];
		}//循环len次，如果数据可以构成32位数据则完整，否则数据不完整
		if(length !=4)//如果不能构成32位数据，按照之前计算的值填充
		{
			int n = 4 - length;//计算需要填充多少个8位数据
			while(n--)
				data[i/4] = (data[i/4] << 8) + space;
		}//到此处可以获取一个完整的32位数据
		j++; // 记录下一个32位数据
	}//j不是4的整数倍，表示最后一个128位数据块没有填满
	while(j < number)//当j比预期要使用的32位数据块小时，需要填充信息直到满足128位
	{
		for (int i = 0; i < 4;i++)//将一个32位数据块填满
		{
			data[j] = (data[j] << 8) + space;
		}
		j++;
	}
	return data;
}

//将加密后的long数组转化为char数组
unsigned char* fpartition(unsigned long* data,int size)
{
	unsigned char *information = new unsigned char[size * 16];
	for (int i = 0; i < size*4;i++)
	{
		for (int j = 0; j < 4;j++)
		{
			information[i * 4 + j] = data[i] >> (3 - j) * 8;
		}
	}
	//cout << "fpartition:" << information << endl;
	return information;
}

//计算初始向量，明文信息的前128比特同时作为明文和密钥，使用加密算法获得密文作为初始密钥，这里可以换成随机数，但是我懒
unsigned long* InitialVector(unsigned long* data)
{
	unsigned long* begins;
	unsigned long *vector;
	unsigned long *rks;
	rks = RoundKey(data);//以明文信息产生轮密钥
	begins = Encrypt(data, rks);//第一次加密，使用第一组明文作为密钥加密自己
	vector = Encrypt(begins, rks);//第二次加密，使用第一次加密的密文作为明文再次加密
	delete[] begins;//释放第一次加密产生的空间
	delete[] rks;//释放用来存放轮密钥的内存
	return vector;
}

//CBC工作模式函数，传入不定长度的明文信息和128位初始密钥,begin字段是为了解密的时候可以访问到初始向量
unsigned char* CBC(unsigned char* information,unsigned long* MK,unsigned long* &begin,int &size)//CBC函数工作模式加密函数
{
	size = 0;//记录传入的明文可以组成多少个128比特数据块
	unsigned long *data = partition(information, size);//data用来存储分割后的明文
	unsigned long *info = new unsigned long[size * 4];//用来记录密文
	unsigned long *rk;
	rk = RoundKey(MK);//产生轮密钥
	ShowH(data, "数字明文", size);
	begin = InitialVector(data);//产生初始向量
	for (int i = 0; i < 4; i++)	//将第一个128比特数据块与初始向量异或运算，获取第一个结果
	{
		data[i] = data[i] ^ begin[i];
	}

	unsigned long* first = Encrypt(data, rk);//获取第一个密文块
	memcpy(info, first, 4 * sizeof(unsigned long));//将该密文块存储到info中
	delete[] first;//删除加密过程中产生密文的空间
	for (int j = 1; j < size;j++)//从第二个(如果有的话)128位明文块开始遍历
	{
		for (int k = 0; k < 4;k++)//将128明文分为四组与前一个密文异或运算
		{
			data[j * 4 + k] = data[j * 4 + k] ^ info[j * 4 + k - 4];
		}
		unsigned long *s = Encrypt((data + 4 * j), rk);//加密该128位明文块
		memcpy(info + 4 * j, s, 4 * sizeof(unsigned long));//拷贝密文到info，4*j表示每个4个存储空间拷贝，因为每次处理的单位位32位数据块
		delete[] s;//释放加密过程产生的内存
	}
	unsigned char *y = new unsigned char[size * 16];//创建内存空间用来存储char类型的密文
	y = fpartition(info, size);//将info这个128位比特的数据转化为单比特数据
	delete[] info;
	return y;
}

//传入没有处理的明文信息，将尾部去除后添加\0后返回
unsigned char* cutends(unsigned long* data,int size)
{
	unsigned int count;//用来存放数据块的最后1个字节的信息
	unsigned char *m;//用于记录明文
	bool temp = false;//false表示没有填充数据，及明文信息刚好128个比特
	count = data[size * 4 - 1] & 0xff;//将最后一个32位数据的前24位置为0剩余的值传入int中
	m = fpartition(data, size);//将128位比特数据转化位char类型的数据
	if (count >= 1 && count <= 16) // 如果count在1~16之间,表示可能有填充的数据
	{
		for (int i = size*16 - count; i < size*16; i++)//遍历最后的count个数据
		{
			if (m[i] == count)//如果这count个数据内容全部为count
			{

				temp = true;//表示有填充数据
			}
			else // 如果有一个数据不是填充数据
			{
				temp = false;
				break;//直接退出
			}
		}
	}
	else // 如果不是填充值
	{
		temp = false;
	}
	if(temp)//如果是填充值
	{
		m[size * 16 - count] = '\0';//将第一个填充值位置设置为"\0"
	}
	else
	{
		m[size * 16] = '\0';//将最后一个128位数据块的后一个位置设置位"\0"
	}
	return m;
}

//传入密文,解密后返回一个字符串，同时解密过程中需要释放填充数据
unsigned char* CBCE(unsigned char*data,unsigned long* MK,unsigned long* begin,int size)//解密算法
{	
	//size表示有多少个128位数据块，degin存放初始向量，MK存放密钥，data存放密文
	unsigned long *info;//用于存放分组后的密文
	unsigned long *cbc = new unsigned long[size * 4];//用来存放解密之后的明文
	unsigned char *m;//应用于存放最终的明文
	unsigned long *rk = RoundKey(MK);
	info = partition(data, size);//将密文重新按照128比特分割
	ShowH(info, "数字密文:", size);
	for (int i = size - 1; i > 0 ;i--)//从末尾遍历
	{
		unsigned long *s = Decrypt((info + 4 * i), rk);//解密
		for (int j = 0; j < 4;j++)
		{
			s[j] = s[j] ^ info[(i - 1) * 4 + j];//与前一个密文异或运算
		}
		memcpy((cbc + 4 * i), s, 4 * sizeof(unsigned long));//拷贝到cbc中
		delete[] s;//释放解密过程中创建的内存
	}
	unsigned long *first = Decrypt(info, rk);//第一个密文块解密后的结果
	for (int j = 0; j < 4;j++)
	{
		first[j] = first[j] ^ begin[j];//与初始向量异或运算
	}
	memcpy(cbc, first, 4 * sizeof(unsigned long));//拷贝到cbc
	delete[] first;//释放中间内存
	ShowH(cbc, "解密后数字明文:", size);
	m = cutends(cbc, size);//处理尾部数据
	return m;
}

int main()
{
	//前128个比特为输入的明文信息
	unsigned char* Y;// 用于存储密文信息
	unsigned char* C;//用于存放解密后的明文
	unsigned long* begin;//用于存放初始向量
	int size = 0;
	unsigned long* MK = new unsigned long[4];//用于存放初始密钥
	unsigned char* information;//用来存放明文的缓冲区
	//MK = inputMK();//输入密钥
	//预设密钥
	MK[0] = 0x01234567;
	MK[1] = 0x89abcdef;
	MK[2] = 0xfedcba98;
	MK[3] = 0x76543210;

	// ShowH(MK, "加密密钥:");
	// unsigned long *rk;
	// rk = RoundKey(MK);//产生轮密钥
	// unsigned long *informations = new unsigned long[4];
	// informations[0] = 0x01234567;
	// informations[1] = 0x89abcdef;
	// informations[2] = 0xfedcba98;
	// informations[3] = 0x76543210;//预设的明文信息，默认输入字符串加密，注释部分可以用来直接设置16进制的数据
	// ShowH(informations, "明文为:");
	// unsigned long *y;
	// y = Encrypt(informations, rk);
	// ShowH(y,"密文为:");

	information = inputinformation();//输入明文
	Y = CBC(information,MK,begin,size);//加密
	C = CBCE(Y, MK, begin, size);//解密

	cout << "解密字符密文:" << C << endl;
	system("pause");
    return 0;
}