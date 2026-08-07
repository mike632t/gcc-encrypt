/*
 * gcc-treyfer.c - Encrypts a stream using the Treyfer cipher
 *
 * Copyright(C) 2026 - MT
 * 
 *    cat gcc-treyfer.c | ./gcc-treyfer -e | base64 > out.txt
 *    cat out.txt | base64 -d | ./gcc-treyfer -d
 * 
 * The Treyfer cipher was designed in 1997 and is simple and compact enough 
 * to allow it to be used on an 8-bit microprocessor like the 8051 or  8080
 * making it suitable for for applications like smart cards.  
 * 
 * Unfortunately the Treyfer cipher was broken when it was discovered  that 
 * it  was vulnerable to slide attacks due to the reuse of the same  8-byte 
 * sub-key every round. 
 * 
 * Th data is read the from stdin and writes the output to stdout in 8 byte 
 * blocks which allows the data to be encrypted or decrypted without having 
 * to read all the data into memory.
 *
 * Since the blocks are a fixed size the final block must be padded to fill
 * the block in the same style as defined in PKCS#7.  If the stream ends on
 * a block boundary, then an additional block containing only padding bytes 
 * will be appended to the output so that the number of bytes of padding is
 * always known.  During decryption the final block is checked to determine
 * the number of padding bytes that were added during encryption.
 * 
 * Deliberately avoids using 'getopt' or 'argparse'.
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
 * Based on https://en.wikipedia.org/wiki/Treyfer
 *
 * 06 Aug 26   0.1   - Initial version - MT
 * 
 * To Do             - Fix up argument parsing
 * 
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>  /* exit */
#include <string.h>

#include <stdarg.h>

#define NAME         "treyfer"
#define VERSION      "0.1"
#define BUILD        "0001"
#define AUTHOR       "MT"

#define NUMROUNDS    32
#define BLOCK_SIZE   8
#define KEY_SIZE     8

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
   fprintf(stdout, "%s: Version %s ", NAME, VERSION);
   if (__DATE__[4] == ' ') fprintf(stdout, "(0"); else fprintf(stdout, "(%c", __DATE__[4]);
   fprintf(stdout, "%c %c%c%c %s %s)", __DATE__[5], __DATE__[0], __DATE__[1], __DATE__[2], &__DATE__[9], __TIME__ );
   fprintf(stdout,"\n");
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
 
void v_error(const char *s_fmt, ...) /* Print formatted error message */
{ 
   va_list t_args;
   va_start(t_args, s_fmt);
   fprintf(stderr, "%s : ", NAME);
   vfprintf(stderr, s_fmt, t_args);
   va_end(t_args);
   exit(0);
}

/* encrypt_block()
 *
 * Encrypts a single block of data in place using the Treyfer block cipher.
 *
 * Each  round processes all bytes in the block, adding the  corresponding
 * key, applying the S-box substitution, rotating the result left, and then
 * storing the result back into the block.
 *
 */
 
void v_encrypt_block(unsigned char c_text[BLOCK_SIZE], unsigned char const c_key[KEY_SIZE])
{
   unsigned int i_count;
   unsigned int i_counter;
   unsigned char c_next;

   /* The first byte becomes the initial value used by the cipher */
   c_next = c_text[0];

   for (i_counter = 0; i_counter < NUMROUNDS; i_counter++)
   {
      for (i_count = 0; i_count < BLOCK_SIZE; i_count++)
      {
         /* Add the key byte for this position */
         c_next = c_next + c_key[i_count];

         /* Apply the nonlinear substitution and add the next block byte */
         c_next = sbox[c_next] + c_text[(i_count + 1) % BLOCK_SIZE];

         /* Rotate left by one bit */
         c_next = (c_next << 1) | (c_next >> 7);

         /* Store the updated byte back into the block */
         c_text[(i_count + 1) % BLOCK_SIZE] = c_next;
      }
   }
}


/* decrypt_block()
 *
 * Decrypts a single block of data in place using the Treyfer block cipher.
 *
 * The  decryption operation reverses the transformations performed  during
 * encryption.  Each block is processed in reverse byte order because  each
 * encryption step depends on the previous updated byte.
 *
 * The encrypted byte is first rotated right, then the S-box transformation
 * added during encryption is reversed.
 *
 */
 
void v_decrypt_block(unsigned char c_text[BLOCK_SIZE], unsigned char const c_key[KEY_SIZE])
{
   int i_count;
   int i_counter;
   unsigned char c_next;
   unsigned char c_substituted;
   unsigned char c_rotated;

   for (i_counter = 0; i_counter < NUMROUNDS; i_counter++)
   {
      /* Process bytes in reverse order to undo encryption */
      for (i_count = BLOCK_SIZE - 1; i_count >= 0; i_count--)
      {
         /* Undo the S-box transformation used during encryption */
         c_next = c_text[i_count] + c_key[i_count];
         c_substituted = sbox[c_next];

         /* Undo the rotate-left operation */
         c_next = c_text[(i_count + 1) % BLOCK_SIZE];
         c_rotated = (c_next >> 1) | (c_next << 7);

         /* Remove the S-box contribution */
         c_text[(i_count + 1) % BLOCK_SIZE] =
             c_rotated - c_substituted;
      }
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
 
void v_encrypt_stream(unsigned char const *h_key) 
{
   unsigned char c_buffer[BLOCK_SIZE];
   unsigned int i_bytes, i_padding, i_count;

   while (true) 
   {
      i_bytes = fread(c_buffer, 1, BLOCK_SIZE, stdin);
      
      if (i_bytes < BLOCK_SIZE) 
      /* If  there  are not enough bytes to fill the block then pad it  out 
       * using the number of remaining bytes */
      {
         i_padding = BLOCK_SIZE - i_bytes;
         for (i_count = i_bytes; i_count < BLOCK_SIZE; i_count++) {
            c_buffer[i_count] = (unsigned char)i_padding;
         }
      }
      /* Encrypt the padded block */
      v_encrypt_block(c_buffer, h_key);
      fwrite(c_buffer, 1, BLOCK_SIZE, stdout);

      if (i_bytes < BLOCK_SIZE) break;
   }
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
 
void v_decrypt_stream(unsigned char const *h_key) 
{
   unsigned char c_buffer[BLOCK_SIZE];
   unsigned char c_pending[BLOCK_SIZE];
   unsigned int i_bytes, i_padding;

   /* Attempt to read the  first block */
   i_bytes = fread(c_buffer, 1, BLOCK_SIZE, stdin); 
   if (i_bytes < BLOCK_SIZE) 
   {
      /* There should be at least one block of data, if there is not then 
       * just give up */
      return; 
   }

   while (true) 
   {
      /* Attempt to read the next block */
      i_bytes = fread(c_pending, 1, BLOCK_SIZE, stdin); 
      /* Decrypt the current block */
      v_decrypt_block(c_buffer, h_key); 

      if (i_bytes == 0) 
      {
         /* If there is not more bytes to read, then this is final block 
          * so we can look ahead to the last byte in the file and to see 
          * how many bytes of data are left */
         i_padding = c_buffer[BLOCK_SIZE - 1];
         if (i_padding > 0 && i_padding <= BLOCK_SIZE) 
         {
            i_bytes = BLOCK_SIZE - i_padding;
            if (i_bytes > 0) fwrite(c_buffer, 1, i_bytes, stdout);
         } 
         else 
            /* If the padding value is invalid or outside the expected 
             * range, print the whole block to avoid discarding data */
            fwrite(c_buffer, 1, BLOCK_SIZE, stdout);
         break;
      }

      /* Print the plain text and get the next block */
      fwrite(c_buffer, 1, BLOCK_SIZE, stdout);
      memcpy(c_buffer, c_pending, BLOCK_SIZE);
   }
}


int main(int argc, char *argv[]) 
{
   const char *s_password = "password";
   unsigned char h_key[KEY_SIZE];
   char b_decrypt = false;
   int i_count, i_index;

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
                  i_index = strlen(argv[i_count]);
                  if (!strncmp(argv[i_count], "--decrypt", i_index)) b_decrypt = true;
                  else if (!strncmp(argv[i_count], "--encrypt", i_index)) b_decrypt = false;
                  else if (!strncmp(argv[i_count], "--help", i_index)) v_about();
                  else if (!strncmp(argv[i_count], "--version", i_index)) v_version();
                  else v_error("invalid option %s\nTry '%s --help' for more information.\n", argv[i_count], NAME);
                  i_index--;
                  break;
               default:
                  v_error("unknown option -- %c\nTry '%s --help' for more information.\n", argv[i_count][i_index], NAME);
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

   /* Set the encryption key from the password */
   memcpy(h_key, s_password, KEY_SIZE);
   
   if (b_decrypt == true) 
      v_decrypt_stream(h_key);
   else
      v_encrypt_stream(h_key);

   return 0;
   }
