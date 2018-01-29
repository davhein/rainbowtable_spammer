#include <iostream>
#include <cstdio>
#include <stdlib.h>
#include "sha256.h"
#include <cstring>

#include <math.h>
#include <secp256k1.h>
#include <thread>
#include <sys/socket.h>

/*
    MYSQL
*/
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>


using namespace std;

char fromhex(char c)
{
    if ( isxdigit(c) )
    {
        if ( isdigit(c) )
        {
            c -= '0';
        } else {
            c = tolower(c);
            c = c - 'a' + 10;
        }
    } else { c = 0; }
    return c;
}

//ne fonctionne pas trop bien
char *hexlify(char *str)
{
    int l,i;
    char* t;
    l = (strlen(str)+1);
    t = static_cast<char*>(malloc(l));

    memset(t,0, sizeof(char));
    if ( &t  )
    {
        for(i=0; i<=l; i++)
        {
            sprintf(t+i, "%02x", str[i]);
            if(i==l){
                sprintf(t+i, NULL, str[i]);
            }
        }
        return t;
    }
    return NULL;
}

//semble OK
char *unhexlify(char *hstr)
{
    int l, i; char *t; char c;
    l = strlen(hstr)/2;
    t = static_cast<char*>(malloc(l));
    if (t)
    {
        for(i=0; i<l; i++)
        {
            c = fromhex( hstr[i+1] ) + 16*fromhex( hstr[i] );
            t[i] = c;
        }
    }
    return t;
}

//semble ok sauf pour les insert, le insert renvoie systématiquement des exceptions.
int connexion_mysql(string host,string user,string passwd,string database, int port,string query)
{
	cout << endl;

	try {
	  sql::Driver *driver;
	  sql::Connection *con;
	  sql::Statement *stmt;
	  sql::ResultSet *res;
	  /* Create a connection */
	  driver = get_driver_instance();
	  con = driver->connect("tcp://"+host+":"+to_string(port), user, passwd);
	  /* Connect to the MySQL test database */
	  con->setSchema(database);
          stmt = con->createStatement();
	  res = stmt->executeQuery(query);
	  while (res->next()) {
	  /* Access column data by alias or column name */
	        cout << res->getString("address") << endl;
	  }
	  delete res;
	  delete stmt;
	  delete con;
	} catch (sql::SQLException &e) {
         cout << "# ERR: SQLException in " << __FILE__;
         cout << "(" << __FUNCTION__ << ") on line " ;
         cout << __LINE__ << endl;
         cout << "# ERR: " << e.what();
         cout << " (MySQL error code: " << e.getErrorCode();
         cout << ", SQLState: " << e.getSQLState() << " )" << endl;
         return EXIT_FAILURE;
	}

	cout << endl;

	return EXIT_SUCCESS;
}

string str_rand_generator(int len)
{
    string res="";
    string chars(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "1234567890"
        "+/");
    /*<< We use __random_device as a source of entropy, since we want
         passwords that are not predictable.
    >>*/
    boost::random::random_device rng;

    boost::random::uniform_int_distribution<> index_dist(0, chars.size() - 1);
    for(int i = 0; i < len; ++i) {
        res += chars[index_dist(rng)];
    }
    return res;
}

void get_pkey(unsigned char* pkey)
{
    string temp;
    temp=sha256(str_rand_generator(32));
    std::copy(temp.begin(),temp.end(),pkey);
    pkey[temp.size()]='\0';
    //cout << "taille " << temp.size() << " " << temp << endl;
}

void gest_err(const char* message, void* data){
    cout << message << endl;
    cout << data << endl;
}

void get_pubkey(unsigned char* in_pkey,unsigned char* out_pubkey,char* out_hexpubkey=0)
{
    string res="";
    size_t taille=64;
    int32_t ecount = 0;
    secp256k1_pubkey pubkey;
    secp256k1_context *ctx;
    const char* message = "gest erreur - callback appelé";
    void* data;
    void (*counting_illegal_callback_fn)(const char*,void*) = gest_err;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context_set_error_callback(ctx,counting_illegal_callback_fn,&ecount);
    secp256k1_context_set_illegal_callback(ctx,counting_illegal_callback_fn,&ecount);
    if(secp256k1_ec_pubkey_create(ctx,&pubkey,in_pkey)!=1){
        cout<< "ERROR : pubkey creation is fucken fucked, mate. BIG TIME"<<endl;
    }

    secp256k1_ec_pubkey_serialize(ctx,out_pubkey,&taille,&pubkey,SECP256K1_EC_COMPRESSED);
    /*if (&out_hexpubkey!=0){
        out_hexpubkey=hexlify(static_cast<char*>(static_cast<void*>(out_pubkey)));
    }*/
    secp256k1_context_destroy(ctx);
    //cout << out_pubkey <<endl;
    //cout << out_hexpubkey <<endl;
    //cout << "pub_key : " << static_cast<char*>(static_cast<void*>(out_pubkey)) << endl;
}

int main()
{
    string host = "104.206.242.22";
    string user = "brt";
    string passwd = "Sepavrai#&!";
    string database = "rbt";
    string txt_query = "";
    int port = 33666;
    int i;
    unsigned char pkey[65];//65
    unsigned char bin_pubkey[53];//53
    char* bin_pkey;
    char* hexpubkey;
    freopen("/home/david/output.txt","w",stdout);
    for(i=0;i<100;i++){
        get_pkey(pkey);
        get_pubkey(pkey,bin_pubkey,hexpubkey);
        cout << i << endl;
        cout << pkey << endl;

        bin_pkey = unhexlify(static_cast<char*>(static_cast<void*>(pkey)));
        txt_query = "insert into incoming(address,private) values('";
        txt_query += reinterpret_cast<const char*>(bin_pubkey);
        txt_query += "','";
        txt_query += bin_pkey;
        txt_query += "')";

        cout << txt_query << endl;
        if(connexion_mysql(host,user,passwd,database,port,txt_query)==EXIT_SUCCESS){
            cout<< "Successfull connection and querying"<<endl;
        }else{
            cout<< "ERROR: Connexion unsuccessfull"<<endl;
        }
        cout << "--------------------------------------------" << endl;
    }
    return 0;
}
