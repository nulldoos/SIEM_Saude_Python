# SIEM_Saude_Python

O sistema utiliza expressões regulares (`re`) para parsing estruturado de logs e a biblioteca `watchdog` para monitorar eventos do sistema de arquivos em tempo real. O analisador dispara alertas imediatos nas seguintes situações:

1. **Acesso por IP Externo (Vazamento / Acesso Não Autorizado):**
   - Dispara alerta sempre que um prontuário médico for consultado a partir de um endereço IP que não pertence à rede interna da prefeitura.
2. **Raspagem de Dados (Mass Data Access):**
   - Utiliza uma janela deslizante temporal de **1 hora** por usuário.
   - Dispara alerta se um único usuário visualizar mais de **50 prontuários médicos diferentes** no intervalo de 60 minutos.


## Como executar

Primeiramente precisa ter o python3.8 ou versão acima dele. Para instalar execute:

```pip install -r requirements.txt```

Depois execute o monitor.py (python monitor.py no terminal)

Em outro terminal, execute o script simular.py para gerar requisições de acesso e injetar comportamentos anômalos no log.

