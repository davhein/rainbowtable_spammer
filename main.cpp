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
    temp=sha256(str_rand_generator(rand()%32));
    std::copy(temp.begin(),temp.end(),pkey);
    pkey[temp.size()]='\0';
}

void get_pubkey(unsigned char* in_pkey,unsigned char* out_pubkey)
{
    string res="";
    size_t taille=64;
    secp256k1_context *ctx;
    secp256k1_pubkey pubkey;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    cout<<"context ok";
    if(!secp256k1_ec_pubkey_create(ctx,&pubkey,in_pkey)){
        cout<< "ERROR : pubkey creation is fucken fucked, mate. BIG TIME"<<endl;
    }
    //pour générer le binary
    //pubkey.data;
    secp256k1_ec_pubkey_serialize(ctx,out_pubkey,&taille,&pubkey,SECP256K1_FLAGS_BIT_COMPRESSION);
    secp256k1_context_destroy(ctx);
}

int main()
{
    string host = "";
    string user = "brt";
    string passwd = "Sepavrai#&!";
    string database = "rbt";
    string query = "select address from incoming limit 10";
    int port = 33666;
    int i;
    unsigned char pkey[65];//un char de plus pour le \0
    unsigned char pubkey[53];
    freopen("/home/david/output.txt","w",stdout);
    for(i=0;i<10;i++){
        get_pkey(pkey);
        get_pubkey(pkey,pubkey);
        cout << pkey << ";" << pubkey << std::endl;
    }
    return 0;
    if(connexion_mysql(host,user,passwd,database,port,query)==EXIT_SUCCESS){
	    cout<< "Successfull connection and querying";
    }else{
	    cout<< "ERROR: Connexion unsuccessfull";
    }

    return 0;
}
