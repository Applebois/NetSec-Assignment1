
////////////INCLUDE COLOUR CODE///////////////////
#ifndef _COLORS_
#define _COLORS_
#define RST  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define FRED(x) KRED x RST
#define FGRN(x) KGRN x RST
#define FYEL(x) KYEL x RST
#define FBLU(x) KBLU x RST
#define FMAG(x) KMAG x RST
#define FCYN(x) KCYN x RST
#define FWHT(x) KWHT x RST
#define BOLD(x) "\x1B[1m" x RST
#define UNDL(x) "\x1B[4m" x RST
#endif  /* _COLORS_ */
/////////////END OF INCLUDE COLOR CODE////////////////////


// Server side C/C++ program to demonstrate Socket programming 
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 
#include <cryptopp/files.h> 
#include <cryptopp/sha.h> 
#include <iostream>
#include <fstream>
#include "cryptopp/des.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include <cryptopp/base64.h>
using namespace CryptoPP;   
using namespace std;

void Save(const string& filename, const BufferedTransformation& bt);
void SaveHex(const string& filename, const BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);

//global variable
string SessionKey_encoded,encryptmsg;
string tripledeskey;
string thirdpairkeyfordes;

// global variable AES
string AES_session,IV_session,AES_session_digest,IV_session_digest;
string received_dummy;
int PORT;


string GetStdoutFromCommand(string cmd) {

    string data;
    FILE * stream;
    const int max_buffer = 256;
    char buffer[max_buffer];
    cmd.append(" 2>&1");

    stream = popen(cmd.c_str(), "r");
    if (stream) {
    while (!feof(stream))
    if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
    pclose(stream);
    }
    return data;
 }




int socket()
{
    do{
    cout<<"Enter port number to start the listener"<<endl;
    cin >> PORT;
     if(PORT > 65535 || PORT <1)
    { 
        cout<<"are you dumb ? the port range is \"1 - 65535\" "<<endl;
     }

    }while(PORT > 65535 || PORT < 1);
    printf ("[Server] Listening the port %d successfully.\n", PORT);
    int server_fd, new_socket, valread; 
    struct sockaddr_in address,peer_addr; 
    int opt = 1; 
    int addrlen = sizeof(address); 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, 
                                                  &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons( PORT ); 

    // Forcefully attaching socket to the port 8080 
    if (bind(server_fd, (struct sockaddr *)&address,  
                                 sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, 3) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    } 
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,  
                       (socklen_t*)&addrlen))<0) 
    { 
        perror("accept"); 
        exit(EXIT_FAILURE); 
    } 

    char *ip; 

	        printf("Connection Established\n"); 

    char host[NI_MAXHOST];      // Client's remote name
    char service[NI_MAXSERV];   // Service (i.e. port) the client is connect on
 
    memset(host, 0, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
    memset(service, 0, NI_MAXSERV);
 
    if (getnameinfo((sockaddr*)&address, sizeof(address), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
    {
        string ls = GetStdoutFromCommand("ifconfig eth0 | grep -w inet | awk '{ print $2}'");
	int a =ls.length();
	std::string str2 = ls.substr (0,a-1);     // "think"
        cout <<"connect to ["<<str2 <<"] from (UNKNOWN) ["<<host<<"] "<< service << endl;
    }
	return new_socket ;
}



string grabfilecontent(string filename)
{
 string inputdata,totaldata;
 ifstream file (filename);
  if (file.is_open())
  {
int counter=0;
    while(getline (file,inputdata))
     {
                totaldata=totaldata+inputdata+"\n";
     }
    file.close();
        return totaldata;
  }
}



void keyGen()
{
    AutoSeededRandomPool rng;
    InvertibleRSAFunction privkey;
    privkey.Initialize(rng, 1024);
    // Generate Private Key
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);
    // Generate Public Key
    RSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);	
    system("sudo rm -rf server_file");
    system("mkdir server_file");
    SaveHexPublicKey("server_file/server_publickey.txt", publicKey);
    SaveHexPrivateKey("server_file/server_privatekey.txt", privateKey);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SaveHex(const string& filename, const BufferedTransformation& bt)
{
    HexEncoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}
 
void SaveHexPrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveHex(filename, queue);
}


void SaveHexPublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveHex(filename, queue);
}
 

void SaveContent(string content, string filename)
{
	  ofstream file;
	  file.open (filename);
	  file << content;
	  file.close();
}


string grabprivatekey(string filename)
{
 string inputdata,totaldata;
 ifstream file (filename);
  if (file.is_open())
  {
        getline (file,inputdata);
            file.close();
        return inputdata;
  }
}


string sha1string(string haha)
{
string digest="";
CryptoPPS::SHA1 sha1;
CryptoPP::StringSource(haha, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
std::cout << "Digest: ";
cout<<digest<<endl;
return digest;
}


string recv_send(int new_socket, string message, string comments)
{
    int valread;
    char buffer[1024] = {0}; 
	string compare;
        valread = read( new_socket , buffer, 1024); 
	cout<<"[ Incoming message from client ] : "<<buffer<<endl;
    	send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
    	cout<<"[ Details ] "<<comments<<endl;
return buffer;
}


string send_recv(int socket, string message, string comments)
{
int valread;
char buffer[1024] = {0};
send(socket , message.c_str() , strlen(message.c_str())+1 , 0 );
cout<<"[ Successfully send to Client ] "<<comments<<endl;
valread = read(socket , buffer, 1024); 
cout<<"[ Incoming message from client ] : ";
printf("%s\n",buffer );
return buffer;
}

void sendpacket(int new_socket,string message)
{
        send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
}


void verify(string a, string b)
{

int result = strcmp(a.c_str(), b.c_str());
cout<<"Comparing the strings"<<endl;
if(result==0)
{
	cout<<FRED(BOLD("Verified"));
}
else
{
	cout<<FRED(BOLD("File is tampered"))<<endl;
	exit(0);
}
}


string Encrypt_AES(string publickey,string plaintext,string title)
{
	AutoSeededRandomPool prng;
	InvertibleRSAFunction parameters;
	RSA::PublicKey publicKey(parameters);
	parameters.GenerateRandomWithKeySize(prng,1024);

	//Convert key from bytes to string
	string stringKey,temporary;

///////////////Load Public Key////////////////////
	string ClientPublicKey;
	StringSource decodekey(publickey,true,new HexDecoder( new StringSink(ClientPublicKey)));
	StringSource pubKeySS(ClientPublicKey,true);
	publicKey.Load(pubKeySS);



////////////////Encrypt the AES_session key/////////////////////
	string encrypted;
	RSAES_OAEP_SHA_Encryptor e(publicKey);
	cout<<BOLD(FYEL("[-------ENCRYPTING "));
	cout<<title;
	cout<<BOLD(FYEL(" USING CLIENT PUBLIC KEY----------]"))<<endl;
	cout<<"[Client-PublicKey]" <<publickey;
	cout<<"+"<<endl;
	cout<<"[PlainText AES_"<<title<<"]" <<plaintext<<endl;
	cout<<"="<<endl;
	StringSource EncryptAES_SESS(plaintext, true, new PK_EncryptorFilter(prng,e,(new HexEncoder(new StringSink(encrypted)))));
	cout<<"[ENCRYPTED]"<<encrypted<<endl;
	return encrypted;
}

string convertToString(char* a, int size) 
{	 
    int i; 
    string s = ""; 
    for (i = 0; i < size; i++) { 
        s = s + a[i]; 
    } 
    return s; 
} 


string receivedummy(int new_socket)
{
        char buffer[1024] = {0}; 
	string compare;
        int valread = read( new_socket , buffer, 1024); 
        int b_size = sizeof(buffer) / sizeof(char); 
        string s_b = convertToString(buffer, b_size); 
	received_dummy=s_b;
        return s_b;
}

void generateAES_session()
{
	AutoSeededRandomPool prng;
	string encoded;
	//24 byte, 24*8 = 192bits
	byte key[24];
	prng.GenerateBlock(key, sizeof(key));

	// byte iv[AES::BLOCKSIZE];
	byte iv[24];
	prng.GenerateBlock(iv, sizeof(iv));

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "Key: " << encoded << endl;
	cout <<"Key length in Hex Format "<<encoded.length()<<endl;
	IV_session_digest=sha1string(encoded);
	AES_session=encoded;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "\n\nIV: " << encoded << endl;
	cout <<"IV length in Hex Format "<<encoded.length()<<endl;
	IV_session_digest=sha1string(encoded);
	cout<<endl;
	IV_session=encoded;
}

void AES_Encryption(string temp, string AESiv, string AESkey,int socket,bool haha)
{
string plain;
if(haha==false)
{
        plain = temp;
}
else
{
do
{
cout<<"Enter message send to server"<<endl;
std::getline(std::cin, plain);
if(plain.size()>1024)
{ 
cout<<BOLD(FRED("Message is exceed the length"))<<endl;
}

}while(plain.size()>1024);
}


    string  recovered;
    AutoSeededRandomPool prng;
    string decodedkey,decodediv;
    StringSource s(AESkey, true,(new HexDecoder(
                new StringSink(decodedkey))
       ) // StreamTransformationFilter
      ); // StringSource

     StringSource ss(AESiv, true,(new HexDecoder(
                new StringSink(decodediv))
       ) // StreamTransformationFilter
      ); // StringSource

SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());
SecByteBlock iv((const byte*)decodediv.data(), decodediv.size());


string cipher,encoded;

/*********************************\
\*********************************/
try
{
        cout << "plain text: " << plain << endl;
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv);

        // CFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        StringSource(plain, true,
         new StreamTransformationFilter(e,
        new StringSink(cipher)) // StreamTransformationFilter
        );              // StringSource
        }
        catch (const CryptoPP::Exception &e)
        {
                cerr << e.what() << endl;
                exit(1);
        }

        /*********************************\
        \*********************************/
        // Pretty print
        encoded.clear();
        StringSource(cipher, true, 
        new HexEncoder( new StringSink(encoded)
                ) // HexEncoder
        );  // StringSource
        cout << "cipher text: " << encoded << endl;
        cout<<"encoded length:" << encoded.length()<<endl;
	if(haha==false)
	{
	send_recv(socket,encoded , "Server send \"Ready\" message to Client");
	}
       else
        {
        sendpacket(socket,encoded);
        }
	if(plain=="quit")
	{
	      cout<<FRED(BOLD("PROGRAM TERMINAL GRACEFULLY"))<<endl;
              exit(1);
	}

}



string AES_Decryption(string cipher,string AESiv,string AESkey, int socket,bool haha)
{
    AutoSeededRandomPool prng;
    string decodedkey,decodediv;
    StringSource s(AESkey, true,(new HexDecoder(
                new StringSink(decodedkey))
       ) // StreamTransformationFilter
      ); // StringSource

     StringSource ss(AESiv, true,(new HexDecoder(
                new StringSink(decodediv))
       ) // StreamTransformationFilter
      ); // StringSource

SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());
SecByteBlock iv((const byte*)decodediv.data(), decodediv.size());

    if(haha==false)
    {
    cipher= recv_send(socket, "Server responed \"Received Acknowledge\", sending \"Ready\"", "Acknowledge send from Client");
    }
    else 
    {
    int valread;
    char buffer[1024] = {0}; 
    string compare;
    valread = read(socket , buffer, 1024); 
    cipher=buffer;
    }
    cout<<"Cipher Text : "<<cipher<<endl;
    string rawcipher;
	StringSource ss2(cipher, true,
    	new HexDecoder(
        	new StringSink(rawcipher)
	    ) // HexEncoder
	); // StringSource



    string recovered;
   try
        {
                CFB_Mode<AES>::Decryption d;
                d.SetKeyWithIV(key, sizeof(key), iv);

                // The StreamTransformationFilter removes
                //  padding as required.
                StringSource s(rawcipher, true,
                   new StreamTransformationFilter(d,
       	           new StringSink(recovered)) // StreamTransformationFilter
                );

                cout <<FCYN(BOLD("Message Received: " << recovered <<""<<))<<endl;
		if(recovered=="quit")
		{
			cout<<FRED(BOLD("PROGRAM TERMINAL GRACEFULLY"))<<endl;
			exit(1);
		}
        }
        catch (const CryptoPP::Exception &e)
        {
                cerr << e.what() << endl;
                exit(1);
        }

        /*********************************\
        \*********************************/
	if(haha==false)
	{
		verify("Acknowledge",recovered);
		cout<<FGRN(BOLD("\nAcknowledge Recevied\n\n"))<<endl;
	}
return recovered;
}



string NewAES(string value,string title){
string tmp,reverse;
cout<<"[OLD] ["<<title<<"] :"<<value<<endl;
for(int i=0; i <= value.length();i++)
 {
		tmp[i]=value[value.length()-i];
s		reverse= reverse+tmp[i];
 }
	        cout<<"[NEW] ["<<title<<"] :"<<reverse<<endl<<endl;
		return reverse;
}



int main(int argc, char const *argv[]) 
{ 

   if (getuid())
   {printf("%s", "You are not root!\nPlease Run as root\n"); exit(1);}
   int new_socket=socket(),valread;
   keyGen();
   char *hello = "Received Wink > .. < ";
   string dummy="";
   string sakeofreturn;
   cout<<FBLU(BOLD("-------------------------------------------------------------------\n\nRECEIVING CLIENT PUBLIC KEY\n\n-------------------------------------------------------------------"))<<endl;
   string client_publickey=recv_send(new_socket, hello, "Public key from Client");//send received wink
   SaveContent(client_publickey,"server_file/received_publickey.txt");			//store client public key and public variable no longer used
   string hashvalue=recv_send(new_socket, hello, "Hash value from Client"); // send received wink
   string contentofpublickeytoverify=grabfilecontent("server_file/received_publickey.txt");
   cout<<BOLD(FBLU("---------------------[Received and Verifying the integrity]---------------------\n\n"));
   verify(hashvalue,sha1string(contentofpublickeytoverify));
   receivedummy(new_socket);

   string message="Verified";
   cout<<"\nHold on, while we're sending our result to Client"<<endl;
   sendpacket(new_socket,message);
//   send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
   cout<<"Sent"<<endl<<endl;
   
   cout<<FRED(BOLD("-------------------------------------------------------------------\n\n"));
   cout<<FRED(BOLD("[System] RSA Key is generating"))<<endl;
   cout<<BOLD(FRED("[---------------------Sending Public - Key and Checksum---------------------]\n\n"))<<endl;

   string privatekey=grabprivatekey("server_file/server_privatekey.txt");
   string publickey=grabfilecontent("server_file/server_publickey.txt");

   string encoded;

    StringSource ss(privatekey,true,
        new Base64Encoder(
            new StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource
    cout << "Private Key for Server in Base64"<<endl;
    cout<<"----BEGIN RSA PRIVATE KEY----"<<endl;
    cout << encoded;
    cout<<"----END RSA PRIVATE KEY----\n"<<endl;
    encoded= "";

    StringSource sss(publickey, true,
        new Base64Encoder(
            new StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource

    cout << "Public Key for Server in Base64"<<endl;
    cout<<"----BEGIN PUBLIC KEY----"<<endl;
    cout << encoded;
    cout<<"----END PUBLIC KEY----\n"<<endl;


    cout<<FRED(BOLD("Value of Public Key in Hex format"))<<endl;
    receivedummy(new_socket);

    cout<<publickey<<endl;
    send_recv(new_socket, publickey, "Public Key have sent");
    string publicsha1=sha1string(grabfilecontent("server_file/server_publickey.txt"));
    cout<<FRED(BOLD("\n[SHA -1 ]PUBLIC KEY : "));
    cout<<publicsha1<<"\n"<<endl;
    send_recv(new_socket, publicsha1, "Hash value \"SHA - 1\" of public key sent");
    cout<<"Waiting Integerity Verified from Client"<<endl;

    sendpacket(new_socket,"dummy");
    receivedummy(new_socket);
    cout<<"We recevied a response from Server"<<endl;
    verify("Verified",received_dummy);

    cout<<FRED(BOLD("\n-------------------Complete sending publickey---------------------"))<<endl;
    cout<<FBLU(BOLD("-------------------Generating AES Session Key---------------------"))<<endl;
    generateAES_session();
    cout<<FBLU(BOLD("------------------------------------------------------------------"))<<endl;
//////////////////ENCRYPT AND SEND///////////////////////////
    string AES_Sess_Key=Encrypt_AES(contentofpublickeytoverify,AES_session,"SESSION KEY");
    cout<<BOLD(FYEL("\n\nSending Encrypted Session Key to Client"))<<endl;
    send_recv(new_socket,AES_Sess_Key,"Encrypted AES Session Key");
///////////////////////////////////////////////////////////
////////SEND ENCRYPTED AES SESSION'S CHECKSUM SESSION//////
    cout<<BOLD(FYEL("\n\nSending SHA - 1 FROM ENCRYPTED Session Key to Client"))<<endl;
    send_recv(new_socket,sha1string(AES_Sess_Key),"SHA-1 digest from Encrypted Session Key");

///////////////////////////////////////////////////////////
////////SEND PLAIN AES SESSION'S CHECKSUM SESSION//////////
    cout<<BOLD(FYEL("\n\nSending SHA - 1 FROM PLAIN Session Key to Client"))<<endl;
    send_recv(new_socket,sha1string(AES_session),"SHA-1 digest from Plain Session Key");

    cout<<BOLD(FYEL("-------------------------------------------------------------------"))<<endl<<endl;

//////////////////////////////////////////////////////////
/////////////////ENCRYPT AND SEND/////////////////////////
    string AES_iv=Encrypt_AES(contentofpublickeytoverify,IV_session,"IV");
    cout<<BOLD(FYEL("\n\nSending Encrypted AES IV to client"))<<endl;
    send_recv(new_socket,AES_iv,"Encrypted AES IV");

//    cin.ignore();
////////////////SEND SHA1 CHECKSUM IV/////////////////
    cout<<BOLD(FYEL("\n\nSending SHA - 1 VALUE FROM ENCRYPTED AES IV to client"))<<endl;
    send_recv(new_socket,sha1string(AES_iv),"SHA-1 digest from Encrypted IV Key");

////////////////SEND SHA1 CHECKSUM IV/////////////////
    cout<<BOLD(FYEL("\n\nSending SHA - 1 VALUE FROM PLAIN AES IV to client"))<<endl;
    send_recv(new_socket,sha1string(IV_session),"SHA-1 digest from Plain IV Key");

    cout<<BOLD(FYEL("-------------------------------------------------------------------"))<<endl<<endl;

    cout<<BOLD(FRED("-------------------------------------------------------------------"))<<endl<<endl;
    cout<<FRED(BOLD("TRYING TO RECEIVE ACKNOWLEDGE FLAG FROM CLIENT\n\n-------------------------------------------------------------------"))<<endl;
    string nonevalue="";
    AES_Decryption(nonevalue,IV_session, AES_session, new_socket,false);
    receivedummy(new_socket);
    cout<<FRED(BOLD("-------------------------------------------------------------------\n\nTRYING TO SEND READY FLAG\n\n--------------------------------------------------------------------"))<<endl;
    AES_Encryption("Ready",IV_session, AES_session,new_socket,false);
    cout<<FMAG(BOLD("\n\n\nRE-CREATE new AES-SESSION KEY & IV"))<<endl;
    cout<<FCYN(BOLD("-------------------------------------------------------------------\n\nHANDSHAKE ESTABLISHED\n\n-------------------------------------------------------------------"))<<endl;
    string key=NewAES(AES_session,"AES-KEY");
    string iv=NewAES(IV_session,"AES-IV");
     cin.ignore();
    do
    {
    AES_Decryption(nonevalue,iv,key,new_socket,true);
    AES_Encryption(nonevalue,iv,key,new_socket,true);
    }while(true);

    return 0;
} 
