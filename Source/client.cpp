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

#include "cryptopp/secblock.h"
#include "cryptopp/sha.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"
#include <cryptopp/hex.h>
#include "cryptopp/rsa.h"
#include <cryptopp/files.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <fstream>


#include "cryptopp/seed.h"
#include "cryptopp/hex.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"
///////////////////END OF INCLUDE LIBRARY////////////////////////////

using namespace std;
using namespace CryptoPP;


using namespace CryptoPP;   
using namespace std;
void Save(const string& filename, const BufferedTransformation& bt);
void SaveHex(const string& filename, const BufferedTransformation& bt);
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void sendpacket(int new_socket,string message);

string received_dummy;

int socket()
{
    cout<<"Enter Server IP ADDRESS"<<endl;
    string ip;
    cin>>ip;
    int PORT;
    do{
    cout<<"Enter port number"<<endl;
    cin>>PORT;
    if(PORT > 65535 || PORT <1)
    {
	cout<<"are you dumb ? the port range is \"0 - 65535\" "<<endl;
     }
    }while(PORT > 65535 || PORT < 1);

  int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
	exit(0);
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(PORT); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
	exit(0);
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
	exit(0);
        return -1; 
    }
 	return sock;	
}

void verify(string a, string b)
{

int result = strcmp(a.c_str(), b.c_str());
cout<<"Comparing the strings"<<endl;
if(result==0)
{

        cout<<BOLD(FRED("Verified"));
}
else
{
	cout<<a<<endl;
	cout<<b<<endl;
        cout<<BOLD(FRED("NOT MATCH!"))<<endl;
        exit(0);
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
    system("rm -rf client_file");
    system("mkdir client_file");
    SaveHexPublicKey("client_file/client_publickey.txt", publicKey);
    SaveHexPrivateKey("client_file/client_privatekey.txt", privateKey);
}

void Print(const std::string& label, const std::string& val)
{
   std::string encoded;
   StringSource(val, true,
      new HexEncoder(
         new StringSink(encoded)
      ) // HexEncoder
   ); // StringSource
   std::cout << label << ": " << encoded << std::endl;
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
CryptoPP::SHA1 sha1;
CryptoPP::StringSource(haha, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
return digest;
}



//code from stackoverflow
//https://stackoverflow.com/questions/29050575/how-would-i-load-a-private-public-key-from-a-string-byte-array-or-any-other
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

string Decryption_PKI(string encryptedcontent,string privKey,string title)
{
AutoSeededRandomPool rng;
InvertibleRSAFunction parameters;
parameters.GenerateRandomWithKeySize(rng,1024);
RSA::PrivateKey privateKey(parameters);
string decodedPrivKey;


////Load Private Key
StringSource ss2(privKey,true,(new HexDecoder( new StringSink(decodedPrivKey)))); 	//decode the privkey from hex to symbol stuff
StringSource PrivKeySS(decodedPrivKey,true);		//load it into bytes
privateKey.Load(PrivKeySS);		//load the private key 

RSAES_OAEP_SHA_Decryptor d(privateKey);
string plaintext;
StringSource ss3(encryptedcontent ,true,(new HexDecoder (new PK_DecryptorFilter(rng, d, (new StringSink(plaintext))))));
cout<<"---------------------------------Decryption is in progress-------------------"<<endl;
cout<<BOLD(FRED("[ **"<< title <<" found* ]"));
cout<<plaintext<<"         |"<<" SHA-1 :";
cout<<sha1string(plaintext)<<endl;
cout<<"---------------------------------Process of decryption is completed-----------"<<endl<<endl;
return plaintext;
}

string send_recv(int socket, string message, string comments)
{
int valread;
char buffer[1024] = {0};
send(socket , message.c_str() , strlen(message.c_str())+1 , 0 );
cout<<"[ Successfully send to Server ] "<<comments<<endl;
valread = read(socket , buffer, 1024); 
cout<<"[ Incoming message from server ] : ";
printf("%s\n",buffer ); 
return buffer;
}


string recv_send(int new_socket, string message, string comments)
{
        int valread;
        char buffer[1024] = {0}; 
        valread = read( new_socket , buffer, 1024); 
        cout<<"[ Incoming message from server ] : "<<buffer<<endl;
        send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
        cout<<"[ Details ] "<<comments<<endl;
return buffer;
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


void sendpacket(int new_socket,string message)
{
        send(new_socket , message.c_str() , strlen(message.c_str())+1 , 0 ); 
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
	);		// StringSource
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
        send_recv(socket,encoded , "Client send \"Received\" to Server");
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
      ); // StringSource       if(haha==false)

     StringSource ss(AESiv, true,(new HexDecoder(
                new StringSink(decodediv))
       ) // StreamTransformationFilter
      ); // StringSource

SecByteBlock key((const byte*)decodedkey.data(), decodedkey.size());
SecByteBlock iv((const byte*)decodediv.data(), decodediv.size());

   if(haha==false)
    {
    cipher=recv_send(socket,"Client responed \"Received Ready\"", "Acknowledge send from Client");
//    sendpacket(socket,"Client responed \"Received Ready\"");
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

                cout << FCYN(BOLD("Message Received: " << recovered<<""))<< endl;
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
                verify("Ready",recovered);
                cout<<FGRN(BOLD("\nReady Recevied"))<<endl;
        }
return recovered;
}





string NewAES(string value,string title){
string tmp,reverse;
cout<<"[OLD] ["<<title<<"] :"<<value<<endl;
for(int i=0; i <= value.length();i++)
 {
                tmp[i]=value[value.length()-i];
                reverse= reverse+tmp[i];
 }
                cout<<"[NEW] ["<<title<<"] :"<<reverse<<endl<<endl;
                return reverse;
}




int main()
{
    int sock=socket(),valread;
    char buffer[1024] = {0}; 
    string receive="Received Winked From Client";
    cout<<FRED(BOLD("[System] RSA Key is generating"))<<endl;
    cout<<FRED(BOLD("---------------------Sending Public-Key and Checksum---------------------"))<<endl;
    keyGen();
    string privatekey=grabprivatekey("client_file/client_privatekey.txt");

    string encoded;

    StringSource ss(privatekey,true,
        new Base64Encoder(
            new StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource
    cout << "Private Key for Client in Base64"<<endl;
    cout<<"----BEGIN RSA PRIVATE KEY----"<<endl;
    cout << encoded;
    cout<<"----END RSA PRIVATE KEY----\n"<<endl;
    encoded= "";

    string publickey=grabfilecontent("client_file/client_publickey.txt");
    StringSource sss(publickey, true,
        new Base64Encoder(
            new StringSink(encoded)
        ) // Base64Encoder
    ); // StringSource

    cout<<"----BEGIN PUBLIC KEY----"<<endl;
    cout << encoded;
    cout<<"----END PUBLIC KEY----\n"<<endl;
    cout<<FRED(BOLD("Value of Public Key in Hex format"))<<endl;
    cout<<publickey<<endl;
    send_recv(sock, publickey, "Public Key have sent");
    string publicmd5=sha1string(grabfilecontent("client_file/client_publickey.txt"));
    cout<<FRED(BOLD("\n[SHA -1 ]PUBLIC KEY : "));
    cout<<publicmd5<<"\n"<<endl;
    send_recv(sock, publicmd5, "Hash value \"SHA - 1\" of public key sent");    
    cout<<"Waiting Integerity Verified from Server"<<endl;
    string dummy="serene";
    sendpacket(sock,dummy);	// send 1 dummy value to balance it 
    cout<<"We recevied a response from Server"<<endl;
    verify("Verified",receivedummy(sock));

    cout<<""<<endl;
    cout<<FRED(BOLD("\n---------------------Complete sending publickey---------------------"))<<endl;
    cout<<FBLU(BOLD("---------------------RECEIVING SERVER PUBLIC KEY---------------------\n\n"));
    string message="Send me your public key";
    sendpacket(sock,message);
    string serverpublickey=recv_send(sock, receive, "Public key from Server");//send received wink
    cout<<""<<endl;
    SaveContent(serverpublickey,"client_file/received_publickey.txt");                 //store server public key 
    string hashvalue=recv_send(sock, receive, "Hash value from Client"); // send received wink
    string contentofpublickeytoverify=grabfilecontent("client_file/received_publickey.txt");
    cout<<FBLU(BOLD("[----------------------Received and Verifying the integrity---------------------]"))<<endl;
    verify(hashvalue,sha1string(contentofpublickeytoverify));
    cout<<"\nHold on, while we're sending our result to Server"<<endl;
    receivedummy(sock);
    sendpacket(sock,"Verified");
    cout<<"Sent"<<endl;
    cout<<FRED(BOLD("\n-------------------------------------------------------------------"))<<endl;
    cout<<FBLU(BOLD("Receiving Encrypted AES Session Key from Server"))<<endl;
///////////////////////RECEIVE KEY/////////////////////////
    string Encrypted_AES_SESS_KEY=recv_send(sock,receive,"Encrypted AES Session Key");
    cout<<endl;
    string sha1_AES_SESS_KEY=recv_send(sock,receive,"VALUE OF SHA - 1 FROM \"ENCRYPTED\" AES SESSION KEY");
    cout<<endl;
    string sha1_AES_PLAIN_SESS_KEY=recv_send(sock,receive,"VALUE OF SHA - 1 FROM \"PLAIN\" AES SESSION KEY");
    cout<<endl;
///////////////////////////////////////////////////////

    cout<<FBLU(BOLD("Receiving Encrypted AES IV from Server"))<<endl;

///////////////////////RECEIVE IV////////////////////
    string Encrypted_AES_IV=recv_send(sock,receive,"Encrypted AES IV");
    cout<<endl;
    string sha1_AES_IV=recv_send(sock,receive,"SHA - 1 FROM \"ENCRYPTED\"AES IV");
    cout<<endl;
    string sha1_PLAIN_AES_IV=recv_send(sock,receive,"SHA - 1 FROM \"PLAIN\"AES IV");
    cout<<endl;
/////////////////////////////////////////////////////


    cout<<"Verifying the Intergrity of recieved content"<<endl;
    cout<<"Verifiying integrity of Encrypted AES Session"<<endl;
    verify(sha1_AES_SESS_KEY,sha1string(Encrypted_AES_SESS_KEY));
          ///VERFIYING ENCRYPTED AES IV
    cout<<"\nVerifiying integrity of Encrypted AES IV"<<endl;
    verify(sha1_AES_IV,sha1string(Encrypted_AES_IV));
    cout<<endl;

	cout<<FBLU(BOLD("Process of verifying is almost complete, 20% remaining left"))<<endl;

	///START DECRYPT VERIFYING THE DECRYPTED HASH
    cout<<"\nProcess of decryption is running and \"Verifying PLAIN's AES SESSION hash\""<<endl<<endl;
    string HexSESSION=Decryption_PKI(Encrypted_AES_SESS_KEY,privatekey,"Session Key -->");
    verify(sha1string(HexSESSION),sha1_AES_PLAIN_SESS_KEY);

	///START DECRYPT IV TO VERIFYING THE DECRYPTED HASH
    cout<<"\nProcess of decryption is running to \"Verifying PLAIN's AES IV\""<<endl<<endl;
    string HexIV=Decryption_PKI(Encrypted_AES_IV,privatekey,"    AES IV  -->");
    verify(sha1string(HexIV),sha1_PLAIN_AES_IV);

    cout<<"\nProcess of integrity checking is completed "<<endl<<endl;



    cout<<FRED(BOLD("-------------------------------------------------------------------\n\nTRYING TO SEND ACKNOWLEDGE FLAG\n\n-------------------------------------------------------------------"))<<endl;
    string nonevalue="";
    AES_Encryption("Acknowledge",HexIV,HexSESSION,sock,false);
    sendpacket(sock,dummy);
    cout<<endl<<endl<<endl;
    cout<<FRED(BOLD("-------------------------------------------------------------------\n\nTRYING TO RECEIVE READY FLAG FROM SERVER\n\n-------------------------------------------------------------------"))<<endl;
    AES_Decryption(nonevalue,HexIV, HexSESSION, sock,false);
    cout<<FMAG(BOLD("\n\n\nRE-CREATE new AES-SESSION KEY & IV"))<<endl;
    cout<<FCYN(BOLD("-------------------------------------------------------------------\n\nHANDSHAKE ESTABLISHED\n\n-------------------------------------------------------------------"))<<endl;
    string key=NewAES(HexSESSION,"AES-KEY");
    string iv=NewAES(HexIV,"AES-IV");
    cin.ignore();
    do
    {
    AES_Encryption(nonevalue,iv,key,sock,true);
    AES_Decryption(nonevalue,iv,key,sock,true);
    }while(true);

}
