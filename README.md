# Projecto de Criptografia Aplicada 

## Autores

- **Filipe Pereira**
- **João Lopes**
- **João Vale**

## Introdução

O presente trabalho prático tem como objetivo construir um Serviço de Message Relay que permita a comunicação segura entre utilizadores de uma organização. Para tal, é necessário implementar protocolos de comunicação que garantam confidencialidade, integridade e autenticacão dos intervenientes e garantir que estes protocolos são resistentes à maior quantidade de ataques possível por parte de indivíduos maliciosos.

## Implementação

### Encriptação de mensagens

Para garantir a confidencialidade das mensagens trocadas entre os utilizadores, é utilizada a cifra simétrica [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode). Esta cifra é uma das mais seguras e eficientes atualmente.

### Comunicação Cliente-Servidor

Para garantir uma comunicação segura entre o cliente e o servidor, é feito um *handshake* entre ambos utilizando o protocolo [Station-to-Station](https://en.wikipedia.org/wiki/Station-to-Station_protocol). Este protocolo permite que ambas as partes se autentiquem mutuamente e publicamente, e combinem uma chave de sessão que será utilizada para cifrar as mensagens trocadas entre ambos.

**Funcionamento do protocolo:**

> 1. CLIENTE: inicia a ligação ao servidor.
> 2. SERVIDOR: gera uma chave privada e pública com base numa curva elíptica x25519.
> 3. SERVIDOR: responde com o seu certificado, chave pública gerada e assinatura que contém a chave pública contida no certificado concatenada com a chave pública gerada. A assinatura é feita com a chave privada relativa ao certificado.
> 4. CLIENTE: verifica a autenticidade do certificado e da assinatura do servidor e gera uma chave privada e pública com base numa curva elíptica x25519 se todas as verificações forem bem sucedidas.
> 5. CLIENTE: gera a chave partilhada com base na chave privada que gerou e na chave pública gerada pelo servidor.
> 6. CLIENTE: envia o seu certificado, chave pública gerada e assinatura que contém a chave pública contida no certificado concatenada com a chave pública gerada. A assinatura é feita com a chave privada relativa ao certificado.
> 7. SERVIDOR: verifica a autenticidade do certificado e da assinatura do cliente e gera a chave partilhada com base na chave privada que gerou e na chave pública recebida do cliente.

> Nota: A chave partilhada é derivada utilizando uma função de derivação de chaves (HKDF).

**O protocolo garante:**

- Autenticidade: Valida certificados e assinaturas digitais de ambas as partes.
- Confidencialidade: Utiliza a chave de sessão para cifrar as mensagens trocadas, que só as partes conhecem.
- Integridade: Utiliza a chave de sessão para cifrar as mensagens. Se a mensagem for alterada, o destinatário não conseguirá decifrá-la.

A chave de sessão é gerada sempre que é feita uma ligação entre o cliente e o servidor, mesmo que o cliente já tenha feito uma ligação anteriormente.

### Comunicação Cliente-Cliente

De modo a garantir uma comunicação segura entre clientes, é necessário acordar uma chave de sessão entre ambos sem que o servidor tenha conhecimento da mesma. Para tal, é utilizado o protocolo [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/) que é muito utilizado, conjuntamente com outros protocolos, em aplicações de mensagens como o WhatsApp e o Signal.

**Funcionamento do protocolo:**

> 1. CLIENTE A: gera 2 chave privadas e públicas com base numa curva elíptica x25519, *Identity Key* e *Signed Key*. Gera também N chaves privadas e públicas com base numa curva elíptica x25519, *One-Time Prekeys*.
> 2. CLIENTE A: envia ao servidor a sua *Identity Key*, *Signed Key*, *One-Time Prekeys*, certificado e assinatura que contém a *Signed Key*. A assinatura é feita com a chave privada relativa ao certificado.
> 3. Servidor: verifica a autenticidade do certificado e da assinatura do cliente e guarda a *Identity Key*, *Signed Key*, *One-Time Prekeys*, certificado e assinatura do cliente.
> 4. CLIENTE B: faz o mesmo processo que o CLIENTE A.
> 5. CLIENTE B: quer comunicar com o CLIENTE A. Para tal, pede ao servidor os dados associados ao CLIENTE A e valida a autenticidade dos mesmos.
> 6. CLIENTE B: gera uma chave privada e pública com base numa curva elíptica x25519, *Ephemeral Key*.
> 7. CLIENTE B: gera a chave partilhada que resulta da concatenação de 4 chaves geradas com o algoritmo de Diffie-Hellman: (IK_priv_b - SK_pub_a) + (EK_priv_b - IK_pub_a) + (EK_priv_b - SK_pub_a) + (EK_priv_b - OPK_pub_a).
> 8. CLIENTE B: envia para o servidor a sua *Ephemeral Key* pública e a *One-Time Prekey* pública do CLIENTE A.
> 9. SERVIDOR: guarda as chaves públicas enviadas e a informação associada ao CLIENTE B num local de handshakes e notifica o CLIENTE A que o CLIENTE B quer comunicar com ele quando este se ligar ao servidor, caso não esteja ligado.
> 10. CLIENTE A: liga-se ao servidor e é notificado que o CLIENTE B quer comunicar com ele.
> 11. Servidor: envia ao CLIENTE A a *Identity Key*, *Signed Key*, *Ephemeral Key*, *One-Time Prekey* usada pelo CLIENTE B, certificado e assinatura que contém a *Signed Key* do CLIENTE B.
> 12. CLIENTE A: valida a autenticidade do certificado e da assinatura do CLIENTE B e gera a chave partilhada que resulta da concatenação de 4 chaves geradas com o algoritmo de Diffie-Hellman: (SK_priv_a - IK_pub_b) + (IK_priv_a - EK_pub_b) + (SK_priv_a - EK_pub_b) + (OPK_priv_a - EK_pub_b).
> 13. CLIENTE A: elimina a *One-Time Prekey* usada. O servidor à partida terá eliminado a *One-Time Prekey* usada pelo CLIENTE B assim que a enviou.

> Nota: A chave partilhada é derivada utilizando uma função de derivação de chaves (HKDF).

**O protocolo garante:**

- Autenticidade: Valida certificados e assinaturas digitais de ambas as partes.
- Confidencialidade: Utiliza a chave de sessão para cifrar as mensagens trocadas, que só as partes conhecem.
- Integridade: Utiliza a chave de sessão para cifrar as mensagens. Se a mensagem for alterada, o destinatário não conseguirá decifrá-la.

Neste caso, as chaves geradas são guardadas de ambos os lados para que seja possível comunicar entre os clientes sem a necessidade de repetir o processo custoso de geração de chaves.

### Chaves de Cliente

As chaves dos *Identity Keys*, *Signed Keys*, *One-Time Prekeys* e *Shared Keys* geradas entre clientes são guardadas localmente no cliente. O ficheiro é ecnriptado com uma password que o cliente escolhe, utilizando o algoritmo [CHACha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20). Este ficheiro é atualizado sempre que uma nova chave CLIENTE-CLIENTE é gerada. O ficheiro é carregado para a memória caso exista, quando o cliente incia a aplicação.

## Trabalho Futuro

Apesar de já existir uma implementação funcional do serviço de mensagens, existem ainda algumas melhorias que podem ser feitas:

- Adicionar um serviço de timestamping com um [TSA](https://en.wikipedia.org/wiki/Trusted_timestamping) para garantir que os timestamps das mensagens são válidos.
- Adicionar [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) para garantir que as mensagens são seguras mesmo que as chaves sejam comprometidas.
- Adicionar um sistema de geração de certificados e chaves RSA para os clientes e servidores da organização.
- Adicionar sistema de logs para guardar informação sobre as mensagens trocadas e os handshakes realizados que pode garantir não-repúdio.
- ...

## Conclusão

De um modo geral, o trabalho foi bastante interessante e permitiu-nos por em prática os conhecimentos adquiridos nas aulas. Apesar de ser um trabalho bastante complexo, conseguimos implementar um serviço de mensagens seguro e eficiente que garante a confidencialidade, integridade e autenticidade das mensagens trocadas entre os utilizadores.
