# ✅ Checklist de Implementação – Sistema Seguro de Comunicação

## 🔑 Funcionalidades Básicas
- [ ] Implementar **login de usuário**
- [ ] Implementar **listagem de usuários cadastrados/conectados**
- [ ] Permitir **abertura de canal seguro de comunicação**
- [ ] Implementar **verificação de integridade das mensagens**
- [ ] Implementar **verificação de autenticidade das partes**

---

## 🔒 Confidencialidade
- [ ] Capturar pacotes de rede com **Wireshark**
- [ ] Analisar pacotes para verificar se os dados estão cifrados
- [ ] Implementar **mTLS (Mutual TLS)**
  - [ ] Configurar certificado para o servidor
  - [ ] Configurar certificado para o cliente
  - [ ] Validar certificados em ambas as pontas
- [ ] Confirmar autenticação mútua cliente ⇄ servidor

---

## 🧾 Autenticação
- [ ] Demonstrar que a autenticação valida:
  - [ ] A máquina / aplicação
  - [ ] O usuário da aplicação
- [ ] Implementar **mecanismo de login com certificados digitais**
- [ ] Associar autenticação com:
  - [ ] Criptografia de chave pública
  - [ ] Certificados digitais
- [ ] Gerenciar certificados utilizando **OpenSSL**
  - [ ] Gerar certificados
  - [ ] Assinar certificados
  - [ ] Validar certificados
- [ ] Implementar canal seguro com a biblioteca **TLS do Python**
- [ ] Garantir autenticidade do cliente e do servidor

---

## 🛡️ Integridade
- [ ] Implementar mecanismo de integridade com **HMAC**
- [ ] Utilizar módulos:
  - [ ] `hmac`
  - [ ] `hashlib`
- [ ] Validar integridade de todas as mensagens enviadas
- [ ] Implementar **troca segura de chaves**
  - [ ] Utilizar **Diffie-Hellman**
- [ ] Garantir que o segredo compartilhado:
  - [ ] Não seja transmitido diretamente
  - [ ] Seja usado apenas para HMAC

---

## ✅ Validação Final
- [ ] Comunicação totalmente cifrada
- [ ] Autenticação mútua funcionando corretamente
- [ ] Integridade verificada em todas as mensagens
- [ ] Usuário autenticado separadamente do dispositivo
- [ ] Evidências práticas (Wireshark, logs e testes)

---

## 📁 Documentação e Demonstração
- [ ] Prints do Wireshark
- [ ] Diagrama da arquitetura
- [ ] Relatório técnico da implementação
- [ ] Descrição do processo de geração de certificados
- [ ] Demonstração prática do sistema funcionando

---
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

- AF_INET: Uso de interne
- SOCK_STREAM: Uso de TCP