
/*
* Copyright (C) <2015>  <Han Zhang>

* BotTalker is free software: you can redistribute it and/or modify 
* it under the terms of the GNU General Public License as published 
* by the Free Software Foundation, either version 3 of the License, 
* or (at your option) any later version.

* BotTalker is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.

* Contact information:
* Email: zhanghan0116@gmail.com
*/

void select_random_key(char * , int );
/*
* generate random key
*/

void select_random_iv(char * , int );
/*
* generate random iv
*/

void encrypt_xor(char * , char * , char* , int )
/*
* encrypt data by using XOR
*/

char * encrypt_OpenSSL(EVP_CIPHER_CTX *, char * , int , int * )
/*
* encrypt data by using OpenSSL
*/

char * decrypt_OpenSSL(EVP_CIPHER_CTX *, char *, int )
/*
* decrypt data by using OpenSSL
*/

int get_element_number(char * )
/*
* get the bytes number of key and iv
*/

int extract_key_iv(char * , char * )
/*
* extract the elements of key and iv
*/

int set_encryption_algorithm(char * , EVP_CIPHER_CTX * , char * , char *)
/*
* set OpenSSL encryption algorithm
*/


/* Incrementally update a checksum */
void update_in_cksum(uint16_t , uint16_t , uint16_t )

void update_in_cksum32(uint16_t , uint32_t , uint32_t )
/*
* update IP checksum
*/
