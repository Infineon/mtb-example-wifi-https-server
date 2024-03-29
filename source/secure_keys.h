/******************************************************************************
* File Name: secure_keys.h
*
* Description: This file contains configuration parameters for the secure HTTP
* server and the server security keys such as server certificate, private key,
* and the root CA (certificate authority) to trust the client.
*
* Related Document: See README.md
*******************************************************************************
* Copyright 2020-2024, Cypress Semiconductor Corporation (an Infineon company) or
* an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
*
* This software, including source code, documentation and related
* materials ("Software") is owned by Cypress Semiconductor Corporation
* or one of its affiliates ("Cypress") and is protected by and subject to
* worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
* If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
* non-transferable license to copy, modify, and compile the Software
* source code solely for use in connection with Cypress's
* integrated circuit products.  Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
* reserves the right to make changes to the Software without notice. Cypress
* does not assume any liability arising out of the application or use of the
* Software or any product or circuit described in the Software. Cypress does
* not authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*******************************************************************************/

/*******************************************************************************
* Include guard
*******************************************************************************/
#ifndef SECURE_KEYS_H_
#define SECURE_KEYS_H_

/* HTTPS server certificate. Copy from the HTTPS server certificate
 * generated by OpenSSL (See Readme.md on how to generate a SSL certificate).
 */
#define keySERVER_CERTIFICATE_PEM \
"-----BEGIN CERTIFICATE-----\n"\
"MIIB8jCCAZcCFHaomKL6yYn6sQ2VfnPohiGtvlnLMAoGCCqGSM49BAMCMHsxCzAJ\n"\
"BgNVBAYTAklOMRIwEAYDVQQIDAlLYXJuYXRha2ExEjAQBgNVBAcMCUJlbmdhbHVy\n"\
"dTELMAkGA1UECgwCQ1kxFDASBgNVBAsMC0VuZ2luZWVyaW5nMSEwHwYDVQQDDBht\n"\
"eXNlY3VyZWh0dHBzZXJ2ZXIubG9jYWwwHhcNMjMxMTIxMTMwNjM0WhcNMjYwODE3\n"\
"MTMwNjM0WjB7MQswCQYDVQQGEwJJTjESMBAGA1UECAwJS2FybmF0YWthMRIwEAYD\n"\
"VQQHDAlCZW5nYWx1cnUxCzAJBgNVBAoMAkNZMRQwEgYDVQQLDAtFbmdpbmVlcmlu\n"\
"ZzEhMB8GA1UEAwwYbXlzZWN1cmVodHRwc2VydmVyLmxvY2FsMFkwEwYHKoZIzj0C\n"\
"AQYIKoZIzj0DAQcDQgAET162Mlw7z2MMgN9XsjWZve+atoDMwRgqJHqxIgcKkCJX\n"\
"w4a0jchurR/pnlR63iHrVIudneWUvMUzhMj2vvIJ1DAKBggqhkjOPQQDAgNJADBG\n"\
"AiEAha1dRi9gL0qsMf2SdrTrB/sXUqemsrDQekjK195s1V0CIQCLULlhWxwg66/8\n"\
"+QMFceok6v2OriU817Dh5ZHoVeXkdA==\n"\
"-----END CERTIFICATE-----\n"

/* Private key of the HTTPS server. Copy from the HTTPS server key
 * generated by OpenSSL (See Readme.md on how to create a private key).
 */
#define keySERVER_PRIVATE_KEY_PEM \
"-----BEGIN EC PRIVATE KEY-----\n"\
"MHcCAQEEID1JggssI2woszhZzn92WVXRqO2okcRvPA9FW8FN1YcioAoGCCqGSM49\n"\
"AwEHoUQDQgAET162Mlw7z2MMgN9XsjWZve+atoDMwRgqJHqxIgcKkCJXw4a0jchu\n"\
"rR/pnlR63iHrVIudneWUvMUzhMj2vvIJ1A==\n"\
"-----END EC PRIVATE KEY-----\n"

/* HTTPS client certificate. In this example this is the RootCA
 * certificate so as to verify the HTTPS client's identity. */
#define keyCLIENT_ROOTCA_PEM \
"-----BEGIN CERTIFICATE-----\n"\
"MIICTDCCAfGgAwIBAgIUCHCMb+mwhjvIiw64Qb48kh3deVIwCgYIKoZIzj0EAwIw\n"\
"ezELMAkGA1UEBhMCSU4xEjAQBgNVBAgMCUthcm5hdGFrYTESMBAGA1UEBwwJQmVu\n"\
"Z2FsdXJ1MQswCQYDVQQKDAJDWTEUMBIGA1UECwwLRW5naW5lZXJpbmcxITAfBgNV\n"\
"BAMMGG15c2VjdXJlaHR0cHNlcnZlci5sb2NhbDAeFw0yMzExMjExMzA2MzRaFw0y\n"\
"MzEyMjExMzA2MzRaMHsxCzAJBgNVBAYTAklOMRIwEAYDVQQIDAlLYXJuYXRha2Ex\n"\
"EjAQBgNVBAcMCUJlbmdhbHVydTELMAkGA1UECgwCQ1kxFDASBgNVBAsMC0VuZ2lu\n"\
"ZWVyaW5nMSEwHwYDVQQDDBhteXNlY3VyZWh0dHBzZXJ2ZXIubG9jYWwwWTATBgcq\n"\
"hkjOPQIBBggqhkjOPQMBBwNCAAS5m8ihXU4s3ITJzGnbKQsn+FBdcKqNbvPee6SG\n"\
"m02AvQrqkAcWCufTZxuj+4FrkQEOq4nnH62xXRbIskL7YLVho1MwUTAdBgNVHQ4E\n"\
"FgQU4IWkLF6QR1Kq1hfRPqm1teu747MwHwYDVR0jBBgwFoAU4IWkLF6QR1Kq1hfR\n"\
"Pqm1teu747MwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEApARi\n"\
"ZDKE0y33F5Aj8gO8jYKMcOAff+JMsRdqVpdz0BMCIQDq/aF4vYjInb6/ZxvjirR/\n"\
"azSrWPfeFhvsSOtg4E0C3Q==\n"\
"-----END CERTIFICATE-----\n"

#endif /* SECURE_KEYS_H_ */

/* [] END OF FILE */
