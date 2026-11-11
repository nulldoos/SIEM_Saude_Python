# Análise de logs de prontuários — SIEM Light

Protótipo acadêmico em Python para identificar visualizações suspeitas em um
arquivo centralizado de auditoria. Todos os exemplos usam dados fictícios.

## Objetivo e regras

| Situação | Comportamento |
| --- | --- |
| Um usuário consulta 50 prontuários distintos em menos de 60 minutos | Não dispara alerta de volume |
| O mesmo usuário consulta o 51º prontuário distinto nesse intervalo | Dispara `VOLUME_PRONTUARIOS` |
| Um usuário consulta o mesmo prontuário 100 vezes | Conta um prontuário distinto |
| Uma visualização vem de um IP fora dos CIDRs configurados | Dispara `IP_FORA_DA_REDE` |
| Um IP é privado, mas não pertence aos CIDRs configurados | Também dispara alerta de origem |
| Uma tentativa tem resultado `NEGADO` | Não entra nestas duas regras de visualização |

A janela é móvel: em cada acesso ocorrido em `t`, contam as consultas no
intervalo `(t - 60 minutos, t]`. Um registro com exatamente 60 minutos já fica
fora. Consultas às 12h50 e às 13h10 pertencem à mesma janela, apesar da mudança
de hora no relógio. Cada usuário tem sua própria contagem.

O alerta de volume é emitido na ultrapassagem do limite. Não é repetido a cada
consulta enquanto a contagem permanecer acima do limite. Ele pode ser emitido
novamente quando consultas expirarem e uma nova consulta ultrapassar o limite.

## Executar no Windows, Linux ou macOS

Requer Python 3.10 ou superior. Extraia o ZIP e abra um terminal na pasta
`siem_saude`. No Windows, se o comando `python` não funcionar, use `py`.

Instale a dependência:

```bash
python -m pip install -r requirements.txt
```

No primeiro terminal, inicie o monitor:

```bash
python monitor.py --rede 10.20.0.0/24
```

Espere aparecer a mensagem `Monitorando`. Em um segundo terminal, na mesma
pasta, execute:

```bash
python simular.py
```

O simulador acrescenta 123 registros: dez consultas normais, sessenta consultas
repetidas ao mesmo prontuário, cinquenta e uma consultas a prontuários distintos,
uma visualização de origem externa e uma tentativa negada. Cada execução usa
usuários fictícios diferentes. Resultado esperado: **dois alertas por execução**,
um de volume e um de origem externa.

Os alertas aparecem no primeiro terminal e são acrescentados a
`saida/alertas.jsonl`. O programa cria as pastas necessárias. Encerre com
`Ctrl+C`.

Para ler também um log que já existe:

```bash
python monitor.py --rede 10.20.0.0/24 --desde-inicio
```

Esse modo é uma reprodução histórica: usa os horários dos registros, podendo
gerar alertas sobre fatos antigos. Cada nova reprodução pode acrescentar alertas
repetidos ao arquivo de saída. Por padrão, somente novas linhas são analisadas.

Para autorizar mais de uma faixa:

```bash
python monitor.py --rede 10.20.0.0/24 --rede 10.30.0.0/24
```

Essas redes são exemplos. Substitua pelas faixas efetivamente autorizadas.
Uma faixa IPv6 também pode ser informada com `--rede`.

## Formato do log de entrada

```text
2026-11-06T15:30:00-03:00 usuario=func_001 ip=10.20.0.12 acao=VISUALIZAR prontuario=FICTICIO_007 resultado=SUCESSO
```

| Campo | Significado |
| --- | --- |
| Data e hora | Horário com fuso explícito; `Z` ou deslocamento como `-03:00` |
| `usuario` | Identificador estável do usuário autenticado |
| `ip` | IP de origem validado pela infraestrutura |
| `acao` | A operação realizada; estas regras analisam `VISUALIZAR` |
| `prontuario` | Identificador estável do prontuário, sem conteúdo clínico |
| `resultado` | `SUCESSO` ou `NEGADO` |

Este formato é um contrato didático, **não um formato oficial ou universal do
SUS**. A expressão regular deve ser adaptada à fonte real. A aplicação precisa
registrar a visualização efetiva, o prontuário e a identidade autenticada; um
log que registre apenas login ou requisição genérica não fornece esses dados.
Logs de múltiplos postos precisam chegar previamente ao arquivo central:
este projeto não implementa o transporte ou a coleta remota.

Cada linha deve terminar com uma quebra de linha. Registros incompletos ficam
aguardando o restante; registros inválidos geram aviso sem exibir a linha bruta.

## Como explicar o código

| Parte | Responsabilidade |
| --- | --- |
| `PADRAO_LOG` e `interpretar_linha()` | `re` extrai os campos; `datetime` valida horário e `ipaddress` valida IP |
| `Analisador.analisar()` | Verifica origem e mantém a contagem de prontuários distintos por usuário |
| `HistoricoUsuario` | Guarda o último horário de consulta de cada prontuário e o estado do alerta |
| `LeitorIncremental` | Lê somente os novos bytes e aguarda linhas completas |
| `AvisoAlteracao` | Usa `watchdog` para avisar quando o arquivo muda |
| `processar()` | Interpreta cada registro e grava os alertas no terminal e em JSONL |
| `simular.py` | Produz os cenários fictícios da apresentação |

Roteiro curto: “O sistema de saúde registra quem visualizou cada prontuário,
quando e de qual IP. O watchdog percebe alterações no arquivo. O leitor busca
apenas as novas linhas, e a expressão regular separa os campos. Para cada
visualização bem-sucedida, verificamos se o IP pertence às redes autorizadas e
quantos prontuários diferentes aquele usuário consultou nos últimos sessenta
minutos. Se alguma regra for atendida, registramos um alerta para análise.”

## LGPD e interpretação dos alertas

A LGPD classifica dados referentes à saúde vinculados a uma pessoa como dados
pessoais sensíveis (art. 5º, II) e exige medidas técnicas e administrativas de
segurança (art. 46). O limite de cinquenta prontuários é uma regra deste projeto;
não é um limite estabelecido nesses artigos. Em uma operação real, o parâmetro
deve ser avaliado conforme o perfil de trabalho de cada equipe.

Um alerta indica necessidade de investigação. Pode haver justificativa para
acesso em volume ou acesso remoto autorizado. O programa não bloqueia usuários,
não confirma vazamento e não garante conformidade integral com a LGPD.

Uma consulta por curiosidade a um único cidadão, feita dentro da rede, não é
detectada por estas duas regras. Uma evolução seria correlacionar o acesso com
o vínculo assistencial, a função do profissional e a agenda de atendimento.

Não registre nomes de pacientes, CPF, diagnósticos ou conteúdo do prontuário na
demonstração. Os alertas guardam somente metadados; identificadores e IPs ainda
precisam de controle de acesso, retenção definida e proteção apropriada.

## Limites técnicos do protótipo

- O histórico fica em memória e é perdido ao encerrar o programa. Ao reiniciar
  no modo padrão, a contagem começa vazia; uma janela anterior só é recomposta
  quando os registros correspondentes forem reprocessados.
- Os registros devem chegar em ordem cronológica por usuário. Um registro
  atrasado gera `HORARIO_FORA_DE_ORDEM` e não entra na contagem de volume; a
  regra de origem ainda é avaliada. A coleta real precisa normalizar horários
  e tratar atrasos antes de depender dessa contagem.
- `watchdog` monitora o diretório local, com uma leitura de conferência a cada
  segundo. Um compartilhamento remoto exige avaliar o observador adequado.
- A leitura trata anexação, linhas parciais, rotação observada por renomeação e
  truncamento observado. Truncar e reescrever até ultrapassar o tamanho anterior
  entre duas leituras pode não ser detectado. Escritas no arquivo antigo após a
  troca de arquivo também exigem uma estratégia de coleta mais robusta.
- Em proxy ou VPN, a política de origem depende do IP efetivamente auditado.
  O IP do proxy pode esconder a origem. Não se deve aceitar um cabeçalho de
  origem fornecido por qualquer cliente como fonte confiável.
- Não há autenticação da fonte, armazenamento inviolável, fila durável,
  persistência do histórico nem correlação assistencial. São etapas futuras
  para uma implantação real.

## Verificação

```bash
python -m unittest -v
```

Os testes cobrem o 51º prontuário, repetições, a fronteira de uma hora, a janela
móvel, usuários independentes, fusos, IPv4/IPv6, faixas não autorizadas, acessos
negados, dois alertas simultâneos, horários fora de ordem e leitura incremental.

Validação desta versão: 19 testes aprovados e demonstração com o monitor
`watchdog` ativo, processando 123 registros e produzindo exatamente os dois
alertas esperados. Um evento de alteração sem novos bytes não duplicou alertas.

## Referências oficiais

- LGPD, texto atualizado, Câmara dos Deputados:
  https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html
- LGPD, art. 5º, Senado Federal:
  https://normas.leg.br/?urn=urn:lex:br:federal:lei:2018-08-14;13709!art5
- Watchdog, documentação de uso:
  https://python-watchdog.readthedocs.io/en/stable/quickstart.html
