/*
 * gcc-parve-stream.c - Yet another encryption algorithm...
 *
 * Copyright(C) 2026 - MT
 *
 * A  block based encryption and decryption utility using a modified  Parve
 * cipher.
 *
 *    cat plaintext.txt | ./gcc-modified-parve -e --pass xyzzy | base64
 *
 *    cat ciphertext.txt | base64 -d | ./gcc-modified-parve -d --pass xyzzy 
 *
 * The Parve cipher is based on the Treyfer cipher which was intended to be 
 * simple  and compact enough to allow it to be implemented using an  8-bit 
 * microprocessor like the 8051 or 8080.  
 *
 * Treyfer  was subsequently shown to be vulnerable to slide attacks due to
 * the reuse of the same sub-key in every round.  Parve attempts to address
 * this by varying the key material used during each round while  retaining 
 * its simple byte-oriented substitution and cascading structure.
 *
 * This  implementation further modifies Parve by deriving the 32-byte  key 
 * used  from the supplied password using a custom key-generation  function 
 * and by applying the S-box output to the adjacent byte before rotating it 
 * left.  These changes improve  diffusion while retaining the  lightweight 
 * byte-oriented design.
 *
 * The  resulting construction remains suitable for implementation on 8-bit 
 * microprocessors with limited memory and computational resources.
 *
 * Input data is processed in fixed-size blocks, allowing the stream to  be
 * encrypted  and decrypted without having to load the complete input  into
 * memory.
 *
 * Each  block is read into a buffer, processed, and written to the  output
 * stream before the next block is read.
 *
 * Since the cipher operates on fixed-size blocks, the final block must  be
 * padded  to  the block size using padding compatible with PKCS#7.  If the
 * input  ends exactly on a block boundary, an additional block  containing
 * only padding bytes is appended so that the amount of padding can  always
 * be determined during decryption.
 *
 * During decryption, the final block is checked and the padding is removed
 * before the plaintext is written to the output stream.
 *
 * During informal testing the modified algorithm showed a strong avalanche 
 * effect,  rapid diffusion, good bit balance, statistically  well-balanced 
 * diffusion, and high diffusion efficiency.
 * 
 * This  program is free software: you can redistribute it and/or modify it
 * under  the terms of the GNU General Public License as published  by  the
 * Free  Software Foundation, either version 3 of the License, or (at  your
 * option) any later version.
 *
 * This  program  is distributed in the hope that it will  be  useful,  but
 * WITHOUT   ANY   WARRANTY;   without even   the   implied   warranty   of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You  should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * 15 Jun 14   0.1   - Initial version - MT
 * 
 * To Do             - Generate a random salt and save with ciphertext - MT
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <stdarg.h>
#include <errno.h>


#define NAME         "parve256"
#define VERSION      "0.1"
#define BUILD        "0001"
#define AUTHOR       "MT"

#define NUMROUNDS 32
#define BLOCK_SIZE 16
#define KEY_SIZE 32
#define SALT_SIZE 32

#define KEY_ITERATIONS 65535 

#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define true         1
#define false        0

static const unsigned char sbox[] = {
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 
   0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
   0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 
   0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 
   0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 
   0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 
   0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 
   0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 
   0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 
   0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 
   0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
   0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 
   0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 
   0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 
   0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 
   0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 
   0xb0, 0x54, 0xbb, 0x16
};


void v_version() /* Display version information */
{ 
   fprintf(stdout, "%s: Version %s.%s %s", NAME, VERSION, BUILD, COMMIT_ID);
#if defined(__compiler__)
   if (strlen(__compiler__)) fprintf(stdout, " %s", __compiler__);  /* Include compiler version if defined - it could be defined as a null string */
#endif
   if (__DATE__[4] == ' ') fprintf(stdout, " 0"); else fprintf(stdout, " %c", __DATE__[4]);
   fprintf(stdout, "%c %c%c%c %s %s\n", __DATE__[5],
      __DATE__[0], __DATE__[1], __DATE__[2], &__DATE__[9], __TIME__ );
   fprintf(stdout, "Copyright(C) %s %s\n", __DATE__ +7, AUTHOR);
   fprintf(stdout, "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n");
   fprintf(stdout, "This is free software: you are free to change and redistribute it.\n");
   fprintf(stdout, "There is NO WARRANTY, to the extent permitted by law.\n");
   exit(0);
}

 
void v_about() /* Display help text */
{ 
   fprintf(stdout, "Usage: %s [OPTION]...\n", NAME);
   fprintf(stdout, "Encrypt or decrypt a stream of data.\n\n");
   fprintf(stdout, "  -d, --decrypt            decrypt\n");
   fprintf(stdout, "  -e, --encrypt            encrypt\n");
   fprintf(stdout, "  -?, --help               display this help and exit\n");
   fprintf(stdout, "      --version            output version information and exit\n\n");
   exit(0);
}


void v_error(int i_errno, const char *s_format, ...)  /* Print formatted error message and exit returning errno */
{
   va_list t_args;
   if (!(i_errno)) i_errno = -1;  /* If errno not set return -1 */
   va_start(t_args, s_format);
   fprintf(stderr, "%s: ", NAME);
   vfprintf(stderr, s_format, t_args);
   va_end(t_args);
   exit(i_errno);
}



/* generate_key(*password, *salt, *key)
 * 
 * Generates a fixed length encryption key from the password and salt.
 * 
 */

void v_generate_key(const char *s_password, const unsigned char *h_salt, unsigned char *h_key)
{
   unsigned int i_count, i_counter;  /* Loop counters */
   unsigned int i_current;  /* Current cascading key value */
   unsigned int i_cascade;  /* Password expansion cascade value */
   unsigned int i_state;  /* S-box lookup value */
   unsigned int i_length;  /* Password length */

   i_length = strlen(s_password);

   /*
    * Initialise the internal key state using the supplied salt.
    *
    * The  salt ensures that the same password will produce different  keys
    * when used with different salt values. This mitigates against  attacks 
    * using pre-computed rainbow tables.
    *
    * The  salt is not intended to be secret, it simply makes each password
    * derivation unique.
    */
    
   for (i_count = 0; i_count < KEY_SIZE; i_count++) {
      h_key[i_count] = h_salt[i_count % SALT_SIZE] ^ (unsigned char)i_count;
   }


   /*
    * Password expansion / accumulation stage.
    *
    * A password may be shorter or longer than the final key size.
    *
    * Mixing  every byte of the password into the internal state means that 
    * a password of any length is fully incorporated into the initial key.
    *
    * Using an S-box makes the behaviour non-linear so that a small  change
    * in the password will produce widely different initial keys.
    *
    */
    
   for (i_count = 0; i_count < i_length; i_count++) {

      i_cascade = (unsigned char)i_count ^ h_key[i_count % KEY_SIZE];

      for (i_counter = 0; i_counter < KEY_SIZE; i_counter++) {

         i_cascade ^= h_key[i_counter];

         /*
          * Apply a non-linear substitution step.  By using an S-box we can 
          * ensure that the relationship between the input and output isn't
          * a simple linear operation.
          */

         i_cascade = sbox[i_cascade];

         h_key[i_counter] ^= i_cascade + (unsigned char)(i_counter + i_count);
      }
   }


   /*
    * Key stretching stage.
    *
    * Passwords chosen by humans usually contain relatively little entropy
    * making them vulnerable to brute force attacks.
    *
    * Key stretching increases the amount of computation required for each 
    * guess.  A legitimate user performs this operation once when deriving 
    * the key, while an attacker attempting to guess the password needs to 
    * repeat the same expensive process for every password attempt.
    *
    * Since each round feeds the previous output back through a non-linear
    * transformation  this creates a dependency chain where the final  key
    * depends  on every previous operation with the amount  of  processing 
    * required being determined by the number of iterations used.
    * 
    * Note that on slower systems KEY_ITERATIONS may need to be reduced!
    *
    */

   {
      i_current = 0x5A;  /* Just a random non zero value */

      for (i_count = 0; i_count < KEY_ITERATIONS; i_count++) {

         for (i_counter = 0; i_counter < KEY_SIZE; i_counter++) {
            i_state = h_key[i_counter] ^ i_current ^ (unsigned char)(i_count & 0xFF);
            i_current = sbox[i_state];

            h_key[i_counter] = i_current + (unsigned char)i_counter;
         }
      }
   }
}

/* encrypt_block()
 * 
 * Encrypts an 8-bit block of data using a modified pave cipher.
 * 
 */
 
void v_encrypt_block(unsigned char *text, unsigned char const *key) {
   unsigned char i_cascade;  /* Cascade result into next byte */
   unsigned char i_text;  /* Position of text on substution block */
   unsigned int i_count;
   for (i_count = 0; i_count < BLOCK_SIZE * NUMROUNDS; i_count++) {
      i_text = text[i_count % BLOCK_SIZE] + (key[i_count % KEY_SIZE] ^ (i_count & 0xFF));
      i_cascade = sbox[i_text] + text[(i_count + 1) % BLOCK_SIZE];
      text[(i_count + 1) % BLOCK_SIZE] = (i_cascade << 1) | (i_cascade >> 7);
   }
}

void v_decrypt_block(unsigned char *text, unsigned char const *key) 
{
   unsigned char c_cypher_text;  /* Encrypted text */
   unsigned char i_cascade;  /* Cascade result into next byte */
   unsigned char i_text;  /* Position of text on substution block */
   int i_count;
   
   for (i_count = (BLOCK_SIZE * NUMROUNDS) - 1; i_count >= 0; i_count--) {
      c_cypher_text = text[(i_count + 1) % BLOCK_SIZE];
      i_cascade = (c_cypher_text >> 1) | (c_cypher_text << 7);
      i_text = text[i_count % BLOCK_SIZE] + (key[i_count % KEY_SIZE] ^ (i_count & 0xFF));
      text[(i_count + 1) % BLOCK_SIZE] = i_cascade - sbox[i_text];
   }
}

/* encrypt_stream()
 * 
 * Encrypts each block of data using encrypt_block().
 * 
 * When the end of file is reached then the remaining bytes in the  current 
 * block (which can be all of them) are padded out with the number of bytes 
 * padding required as defined in PKCS#7.
 * 
 */
 
void v_encrypt_stream(unsigned char const *key) 
{
   unsigned char c_buffer[BLOCK_SIZE];
   unsigned int i_bytes;  /* Number of bytes in block read from file */
   unsigned int padding_value;
   int i_count;

   do
   {
      i_bytes = fread(c_buffer, 1, BLOCK_SIZE, stdin);  /* Read the next block from the file */
      if (i_bytes < BLOCK_SIZE)  /* Check that there are enough bytes to fill the block */
      {
         /* Pad the block out using the number of remaining bytes to fill in buffer */
         padding_value = BLOCK_SIZE - i_bytes;  
         for (i_count = i_bytes; i_count < BLOCK_SIZE; i_count++) 
         {
            c_buffer[i_count] = (unsigned char)padding_value;
         }
      }

      v_encrypt_block(c_buffer, key);  /* Encryot the whole block */
      fwrite(c_buffer, 1, BLOCK_SIZE, stdout);
   } while ( i_bytes == BLOCK_SIZE );
}

/* decrypt_stream()
 * 
 * Decrypts each block of data using decrypt_block().
 * 
 * To correctly detect the number of bytes padding used to ensure that each 
 * that block of data is a fixed size this routine uses a two-block sliding 
 * window to read the next block before the current block is decrypted. 
 * 
 * When the end of file is reached then the number of bytes of padding will
 * be known and the padding can be discarded without corrupting the data.
 * 
 */
 
void v_decrypt_stream(unsigned char const *key) 
{
   unsigned char current_block[BLOCK_SIZE];
   unsigned char next_block[BLOCK_SIZE];
   unsigned char padding_bytes;
   unsigned int current_bytes, next_bytes, payload_len;

   /* Prefetch first block */
   current_bytes = fread(current_block, 1, BLOCK_SIZE, stdin);
   if (current_bytes < BLOCK_SIZE) {
      /* There should be at least one block of data, if there is not then 
       * just give up */
      return; 
   }

   while (1) {
      /* Attempt to read the next block */
      next_bytes = fread(next_block, 1, BLOCK_SIZE, stdin);
      
      /* Decrypt the current block */
      v_decrypt_block(current_block, key);

      if (next_bytes == 0) {
         /* If there are no more bytes, then this is final block so look
          * ahead  to the last byte in the file and check how many bytes 
          * are left */
         padding_bytes = current_block[BLOCK_SIZE - 1];
         if (padding_bytes > 0 && padding_bytes <= BLOCK_SIZE) {
            payload_len = BLOCK_SIZE - padding_bytes;
            if (payload_len > 0) {
               fwrite(current_block, 1, payload_len, stdout);
            }
         } else {
            /* If the padding value is invalid or outside the expected 
             * range, print the whole block to avoid discarding data */
            fwrite(current_block, 1, BLOCK_SIZE, stdout);
         }
         break; 
      }

      /* Print the plain text and copy the next block to the current block */
      fwrite(current_block, 1, BLOCK_SIZE, stdout);
      memcpy(current_block, next_block, BLOCK_SIZE);
   }
}


int main(int argc, char *argv[]) 
{
   const unsigned char c_static_salt[SALT_SIZE] = 
      { 0x4e, 0xc8, 0xb0, 0xd6, 0xdb, 0xe4, 0x76, 0xc7, 
        0xe9, 0x95, 0x73, 0x5f, 0xcd, 0x4a, 0xa3, 0x3b,
        0x6e, 0xa3, 0xef, 0x2d, 0x32, 0xe7, 0x87, 0x2f, 
        0xa0, 0x49, 0xa3, 0x5f, 0x35, 0x13, 0xa0, 0xb9,
      };
   const char *s_password = NULL;
   unsigned char h_key[KEY_SIZE];
   char b_decrypt = false;
   int i_count, i_index, i_offset;

   /* Parse command line options without using 'getopt' or 'argeparse' */
   for (i_count = 1; i_count < argc; i_count++) 
   {
      if (argv[i_count][0] == '-') 
      {
         i_index = 1;
         while (argv[i_count][i_index] != 0) 
         {
            switch (argv[i_count][i_index]) 
            {
               case 'd': b_decrypt = true; break;
               case 'e': b_decrypt = false; break;
               case '-':
                  i_index = MAX(strlen(argv[i_count]), 3);
                  if (!strncmp(argv[i_count], "--decrypt", i_index)) b_decrypt = true;
                  else if (!strncmp(argv[i_count], "--encrypt", i_index)) b_decrypt = false;
                  else if (!strncmp(argv[i_count], "--help", i_index)) v_about();
                  
                  else if (!strncmp(argv[i_count], "--password", i_index))
                  {
                     if (i_count + 1 < argc)
                     {
                        s_password = argv[i_count + 1];
                        if (i_count + 2 < argc)  /* Remove the parameter from the arguments */
                           for (i_offset = i_count + 1; i_offset < argc - 1; i_offset++)
                              argv[i_offset] = argv[i_offset + 1];
                        argc--;
                     }
                     else
                        v_error(EINVAL, "option requires an argument -- '%s'\n", argv[i_count]);
                  }
                  
                  else if (!strncmp(argv[i_count], "--version", i_index)) v_version();
                  else v_error(EINVAL, "invalid option %s\nTry '%s --help' for more information.\n", argv[i_count], NAME);
                  i_index--;
                  break;
               default:
                  v_error(EINVAL, "unknown option -- %c\nTry '%s --help' for more information.\n", argv[i_count][i_index], NAME);
            }
            i_index++;
         }
         if (argv[i_count][1] != 0) 
         {
            for (i_index = i_count; i_index < argc - 1; i_index++) argv[i_index] = argv[i_index + 1];
            argc--; i_count--;
         }
      }
   }

   if (s_password)
   {
      v_generate_key(s_password, c_static_salt, h_key); /* Generate a 32-byte encryption key from the s_password string */
      if (b_decrypt)  /* Default to encryption */
         v_decrypt_stream(h_key);
      else
         v_encrypt_stream(h_key);
   }
   else
      v_error(EINVAL,"no password specified.\n");

   return EXIT_SUCCESS;
   }

