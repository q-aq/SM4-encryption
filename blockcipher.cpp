//SM4�����㷨
#include<iostream>
#include<stdio.h>
#include<math.h>
#include<time.h>
#include<stack>
#define MAX 102400
using namespace std;
//S�нṹ����
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

//����Կ���ɹ�������Ҫ�Ĳ���
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


//�ú�������8λ���ݣ�����8λ����
//S�к���
static const unsigned char S(unsigned char information)//����һ���ֽ����ݣ�ͨ������Sbox��ȡ����ֽ�
{
    int number = information;
    int y = number % 16;
    int x = number / 16;
    return SboxTable[x][y];
}

//�ú�������32λ���ݣ�����32λ����
unsigned long ls(unsigned long A)//�����Ա任,��������0xab125d93
{
	unsigned char* b = new unsigned char[4];
	unsigned long B = 0;
	unsigned char a[4];
	//printf("%x\n", A);
	//��32λ����ת��Ϊ4��8λ���ݣ��������������
	a[3] = A % 256;
	a[2] = (A / 256) % 256;
	a[1] = (A / 256 / 256) % 256;
	a[0] = A / 256 / 256 / 256;
	//printf("\n");
	for (int i = 0; i < 4; i++)
	{
		b[i] = S(a[i]);//�������S�к���
	}
	for (int i = 0; i < 4; i++)
	{
		B += b[i] * (int)pow(256,3-i);//��S�к�����������λһ��32λ����
	}
	return B;
}

//�ú�������32λ���ݣ�����32λ����
unsigned long LeftShift(unsigned long a,int n)//ѭ������nλ����
{
	for (int i = 0; i < n;i++)
	{
		unsigned long head = (a >> 31) & 0x1;//��a�����ƶ�31λʹ�õ�32λ����λ�����λ����0x1���룬����λ��Ϊ0����ȡ��32λ����
		//printf("head = %ld\n", head);
		unsigned long space = a & (~0x80000000);//��a��32λ��Ϊ0����ֹ32λΪ1��long��64λ֮�����ƻᵼ��33λ��Ϊ0
		//printf("space = %x\n", space);
		unsigned long other = (space << 1) &(~0x1); //��a�����ƶ�1λ
		//printf("other = %x\n", other);
		a = other + head;//���õ����ַ��������λ��ӣ������λ���ӵ������λ
	}
	return a;
}

//�ú�������32λ���ݣ�����32λ����
unsigned long L(unsigned long B)//���Ա任L
{
	unsigned long C;
	unsigned long B2 = LeftShift(B, 2);//��ʾBѭ������2λ
	unsigned long B10 = LeftShift(B, 10);//��ʾBѭ������10λ
	unsigned long B18 = LeftShift(B, 18);//��ʾBѭ������18λ
	unsigned long B24 = LeftShift(B, 24);//��ʾѭ������24λ
	C = B ^ B2 ^ B10 ^ B18 ^ B24;//������������
	return C;
}

//�ú�������32λ���ݣ�����32λ����
unsigned long L1(unsigned long B)//���Ա任L`
{
	unsigned long C;
	unsigned long B13 = LeftShift(B, 13);
	unsigned long B23 = LeftShift(B, 23);
	C = B ^ B13 ^ B23;
	return C;
}

//�ú�������32λ���ݣ�����32λ����
unsigned long T(unsigned long X)//T�任
{
	unsigned long D;
	D = L(ls(X));//���Ա任�ͷ����Ա任��Ϲ��ɺϳɱ任T
	return D;
}

//�ú�������32λ���ݣ�����32λ����
unsigned long T1(unsigned long X)//T`�任
{
	unsigned long D;
	D = L1(ls(X));
	return D;
}

//�ú�������4��32λ�ļ�����Կ,����rk���飬����32��32λ����Կ
unsigned long* RoundKey(unsigned long* MK)//����Կ���ɺ���
{
	unsigned long K[36];
	unsigned long* rk = new unsigned long[32];
	for (int i = 0; i < 4;i++)
	{
		K[i] = MK[i] ^ FK[i];
	}//����K0��K1��K2��K3
	for (int i = 0; i < 32;i++)
	{
		rk[i] = K[i + 4] = K[i] ^ T1(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i]);
	}
	return rk;
}

//�ú�������4��32λ���ݺ�һ��32λ����Կ,����32λ����
unsigned long F(unsigned long X0,unsigned long X1,unsigned long X2,unsigned long X3,unsigned long rk)//�ֺ���
{
	unsigned long D;
	D = X0 ^ T(X1 ^ X2 ^ X3 ^ rk);
	return D; // �����ΪX[i+4];
}

//����4��32λ�������ݹ�128���أ�����32������Կ���4��32λ����
unsigned long* Encrypt(unsigned long* X,unsigned long* rk)//���ܺ���
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
	}//32���۵���
	//�������
	Y[0] = data[35];
	Y[1] = data[34];
	Y[2] = data[33];
	Y[3] = data[32];
	return Y;
}

//����4��32λ�������ݣ���32������Կ������ܺ�������Կ��ͬ�����Ƿ���
unsigned long* Decrypt(unsigned long* Y,unsigned long* rk)//���ܺ���
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

//����32���ݣ��Զ��������,����������
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

//����һ��ָ�룬��16�������������string����Ϊ�������ʾ��Ϣ��size��ʾ��Ϊ���ٿ������������и���
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

//��4��32λ��ʼ��Կ
unsigned long* inputMK()
{
	cout << "������128λ��Կ(��Ϊ��������ÿ�����32����):";
	unsigned long *mk = new unsigned long[4];
	for (int i = 0; i < 4;i++)
	{
		cin >> mk[i];
	}
	return mk;
}

//������Ҫ���ܵ���Ϣ���������κ����͵���Ϣ������һ��char*����
unsigned char* inputinformation()
{
	cout << "��������Ҫ���ܵ���Ϣ:";
	unsigned char *information = new unsigned char[MAX];
	char *buffer = new char[MAX];
	cin.getline(buffer, MAX + 1);
	information =(unsigned char*)buffer;
	return information;
}

//����������Ϣ���ֳ���ȷ��(��\0��β)����������32λΪ������λ��ÿ4��Ϊһ�飬���ɶ���128λ���ģ������������Ϣʹ��ʣ���ֽڳ������
unsigned long* partition(unsigned char* information,int &size)
{
	int len = 0;
	if(size == 0)//���sizeΪ0��ʾ�ڼ��ܹ����е��ô˺���������Ҫ����ֽڶ�ȡ����"\0"��ʾ��β
	{
	while(information[len] != '\0')
		len++;//len��ʾ�ж��ٸ�8λ��Ч���ݿ�
	size = len / 16 + (len % 16 != 0 ? 1 : 0);//size��ʾ�ж��ٸ�128λ��Ч���ݿ�
	}
	else//���size��Ϊ0��ʾ�ڽ��ܵ�ʱ����ô˺���������������len�Ĺ��̣�ֱ��ͨ��size��ֵ�������len
	{
		len = size * 16;
	}
	int number = size*4;//number��ʾ�ж��ٸ�32λ��Ч���ݿ�
	int space = size * 16 - len;//��¼�ж��ٸ��ֽ�Ϊ�գ��������
	//  cout << "len::" << len << endl;
	//  cout << "size::" << size << endl;
	//  cout << "number::" << number << endl;
	//  cout << "space::" << space << endl;
	unsigned long *data = new unsigned long[number]; // ��̬�滮����ռ䣬������ŷ������ģ�ÿ�ĸ�Ϊһ��
	for (int i = 0; i < number;i++)//��dataȫ����Ϊ0
	{
		data[i] = 0;
	}
	int j = 0;//������¼��ǰ���뵽�����е�32λ���ݸ���
	for (int i = 0; i < len;i+=4)//ÿ32���ֽ�һѭ����ͨ��i��kһ�����
	{
		int length = (len - i >= 4) ? 4 : len - i;//�ж�ʣ�೤���ܷ񹹳�һ��32λ���ݣ������Ƿ������Ϣ
		for (int k = 0; k < length;k++)
		{
			data[i/4] = (data[i/4] << 8) + information[i + k];
		}//ѭ��len�Σ�������ݿ��Թ���32λ�������������������ݲ�����
		if(length !=4)//������ܹ���32λ���ݣ�����֮ǰ�����ֵ���
		{
			int n = 4 - length;//������Ҫ�����ٸ�8λ����
			while(n--)
				data[i/4] = (data[i/4] << 8) + space;
		}//���˴����Ի�ȡһ��������32λ����
		j++; // ��¼��һ��32λ����
	}//j����4������������ʾ���һ��128λ���ݿ�û������
	while(j < number)//��j��Ԥ��Ҫʹ�õ�32λ���ݿ�Сʱ����Ҫ�����Ϣֱ������128λ
	{
		for (int i = 0; i < 4;i++)//��һ��32λ���ݿ�����
		{
			data[j] = (data[j] << 8) + space;
		}
		j++;
	}
	return data;
}

//�����ܺ��long����ת��Ϊchar����
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

//�����ʼ������������Ϣ��ǰ128����ͬʱ��Ϊ���ĺ���Կ��ʹ�ü����㷨���������Ϊ��ʼ��Կ��������Ի������������������
unsigned long* InitialVector(unsigned long* data)
{
	unsigned long* begins;
	unsigned long *vector;
	unsigned long *rks;
	rks = RoundKey(data);//��������Ϣ��������Կ
	begins = Encrypt(data, rks);//��һ�μ��ܣ�ʹ�õ�һ��������Ϊ��Կ�����Լ�
	vector = Encrypt(begins, rks);//�ڶ��μ��ܣ�ʹ�õ�һ�μ��ܵ�������Ϊ�����ٴμ���
	delete[] begins;//�ͷŵ�һ�μ��ܲ����Ŀռ�
	delete[] rks;//�ͷ������������Կ���ڴ�
	return vector;
}

//CBC����ģʽ���������벻�����ȵ�������Ϣ��128λ��ʼ��Կ,begin�ֶ���Ϊ�˽��ܵ�ʱ����Է��ʵ���ʼ����
unsigned char* CBC(unsigned char* information,unsigned long* MK,unsigned long* &begin,int &size)//CBC��������ģʽ���ܺ���
{
	size = 0;//��¼��������Ŀ�����ɶ��ٸ�128�������ݿ�
	unsigned long *data = partition(information, size);//data�����洢�ָ�������
	unsigned long *info = new unsigned long[size * 4];//������¼����
	unsigned long *rk;
	rk = RoundKey(MK);//��������Կ
	ShowH(data, "��������", size);
	begin = InitialVector(data);//������ʼ����
	for (int i = 0; i < 4; i++)	//����һ��128�������ݿ����ʼ����������㣬��ȡ��һ�����
	{
		data[i] = data[i] ^ begin[i];
	}

	unsigned long* first = Encrypt(data, rk);//��ȡ��һ�����Ŀ�
	memcpy(info, first, 4 * sizeof(unsigned long));//�������Ŀ�洢��info��
	delete[] first;//ɾ�����ܹ����в������ĵĿռ�
	for (int j = 1; j < size;j++)//�ӵڶ���(����еĻ�)128λ���Ŀ鿪ʼ����
	{
		for (int k = 0; k < 4;k++)//��128���ķ�Ϊ������ǰһ�������������
		{
			data[j * 4 + k] = data[j * 4 + k] ^ info[j * 4 + k - 4];
		}
		unsigned long *s = Encrypt((data + 4 * j), rk);//���ܸ�128λ���Ŀ�
		memcpy(info + 4 * j, s, 4 * sizeof(unsigned long));//�������ĵ�info��4*j��ʾÿ��4���洢�ռ俽������Ϊÿ�δ���ĵ�λλ32λ���ݿ�
		delete[] s;//�ͷż��ܹ��̲������ڴ�
	}
	unsigned char *y = new unsigned char[size * 16];//�����ڴ�ռ������洢char���͵�����
	y = fpartition(info, size);//��info���128λ���ص�����ת��Ϊ����������
	delete[] info;
	return y;
}

//����û�д����������Ϣ����β��ȥ�������\0�󷵻�
unsigned char* cutends(unsigned long* data,int size)
{
	unsigned int count;//����������ݿ�����1���ֽڵ���Ϣ
	unsigned char *m;//���ڼ�¼����
	bool temp = false;//false��ʾû��������ݣ���������Ϣ�պ�128������
	count = data[size * 4 - 1] & 0xff;//�����һ��32λ���ݵ�ǰ24λ��Ϊ0ʣ���ֵ����int��
	m = fpartition(data, size);//��128λ��������ת��λchar���͵�����
	if (count >= 1 && count <= 16) // ���count��1~16֮��,��ʾ��������������
	{
		for (int i = size*16 - count; i < size*16; i++)//��������count������
		{
			if (m[i] == count)//�����count����������ȫ��Ϊcount
			{

				temp = true;//��ʾ���������
			}
			else // �����һ�����ݲ����������
			{
				temp = false;
				break;//ֱ���˳�
			}
		}
	}
	else // ����������ֵ
	{
		temp = false;
	}
	if(temp)//��������ֵ
	{
		m[size * 16 - count] = '\0';//����һ�����ֵλ������Ϊ"\0"
	}
	else
	{
		m[size * 16] = '\0';//�����һ��128λ���ݿ�ĺ�һ��λ������λ"\0"
	}
	return m;
}

//��������,���ܺ󷵻�һ���ַ�����ͬʱ���ܹ�������Ҫ�ͷ��������
unsigned char* CBCE(unsigned char*data,unsigned long* MK,unsigned long* begin,int size)//�����㷨
{	
	//size��ʾ�ж��ٸ�128λ���ݿ飬degin��ų�ʼ������MK�����Կ��data�������
	unsigned long *info;//���ڴ�ŷ���������
	unsigned long *cbc = new unsigned long[size * 4];//������Ž���֮�������
	unsigned char *m;//Ӧ���ڴ�����յ�����
	unsigned long *rk = RoundKey(MK);
	info = partition(data, size);//���������°���128���طָ�
	ShowH(info, "��������:", size);
	for (int i = size - 1; i > 0 ;i--)//��ĩβ����
	{
		unsigned long *s = Decrypt((info + 4 * i), rk);//����
		for (int j = 0; j < 4;j++)
		{
			s[j] = s[j] ^ info[(i - 1) * 4 + j];//��ǰһ�������������
		}
		memcpy((cbc + 4 * i), s, 4 * sizeof(unsigned long));//������cbc��
		delete[] s;//�ͷŽ��ܹ����д������ڴ�
	}
	unsigned long *first = Decrypt(info, rk);//��һ�����Ŀ���ܺ�Ľ��
	for (int j = 0; j < 4;j++)
	{
		first[j] = first[j] ^ begin[j];//���ʼ�����������
	}
	memcpy(cbc, first, 4 * sizeof(unsigned long));//������cbc
	delete[] first;//�ͷ��м��ڴ�
	ShowH(cbc, "���ܺ���������:", size);
	m = cutends(cbc, size);//����β������
	return m;
}

int main()
{
	//ǰ128������Ϊ�����������Ϣ
	unsigned char* Y;// ���ڴ洢������Ϣ
	unsigned char* C;//���ڴ�Ž��ܺ������
	unsigned long* begin;//���ڴ�ų�ʼ����
	int size = 0;
	unsigned long* MK = new unsigned long[4];//���ڴ�ų�ʼ��Կ
	unsigned char* information;//����������ĵĻ�����
	//MK = inputMK();//������Կ
	//Ԥ����Կ
	MK[0] = 0x01234567;
	MK[1] = 0x89abcdef;
	MK[2] = 0xfedcba98;
	MK[3] = 0x76543210;

	// ShowH(MK, "������Կ:");
	// unsigned long *rk;
	// rk = RoundKey(MK);//��������Կ
	// unsigned long *informations = new unsigned long[4];
	// informations[0] = 0x01234567;
	// informations[1] = 0x89abcdef;
	// informations[2] = 0xfedcba98;
	// informations[3] = 0x76543210;//Ԥ���������Ϣ��Ĭ�������ַ������ܣ�ע�Ͳ��ֿ�������ֱ������16���Ƶ�����
	// ShowH(informations, "����Ϊ:");
	// unsigned long *y;
	// y = Encrypt(informations, rk);
	// ShowH(y,"����Ϊ:");

	information = inputinformation();//��������
	Y = CBC(information,MK,begin,size);//����
	C = CBCE(Y, MK, begin, size);//����

	cout << "�����ַ�����:" << C << endl;
	system("pause");
    return 0;
}