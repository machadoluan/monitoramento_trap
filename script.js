// app.js - Receptor de Traps SNMP
const snmp = require('net-snmp');
const fs = require('fs');
const path = require('path');

class SNMPTrapReceiver {
    constructor() {
        this.logFile = path.join(__dirname, 'logs', 'traps.log');
        this.trapCount = 0;
        this.init();
    }

    init() {
        console.log('🔥 Iniciando receptor de traps SNMP...');
        console.log('📂 Logs salvos em:', this.logFile);
        
        // Garantir que a pasta logs existe
        if (!fs.existsSync(path.dirname(this.logFile))) {
            fs.mkdirSync(path.dirname(this.logFile), { recursive: true });
        }

        this.startTrapReceiver();
    }

    startTrapReceiver() {
        // Usar apenas receptor UDP que funciona para tudo
        console.log('🔧 Configurando receptor UDP universal...');
        this.startUDPReceiver();
    }

    startUDPReceiver() {
        const dgram = require('dgram');
        const server = dgram.createSocket('udp4');

        server.on('message', (msg, rinfo) => {
            this.trapCount++;
            const timestamp = new Date().toISOString();
            
            console.log(`\n📨 DADOS RECEBIDOS #${this.trapCount}`);
            console.log('⏰ Timestamp:', timestamp);
            console.log('🌐 Remetente:', rinfo.address + ':' + rinfo.port);
            console.log('📊 Tamanho:', msg.length, 'bytes');
            
            // Primeiro tentar como SNMP
            if (this.tryParseAsSNMP(msg)) {
                console.log('📋 Tipo: SNMP Trap (detectado)');
            } else {
                console.log('📋 Tipo: UDP Data');
                
                // Tentar decodificar como texto
                try {
                    const textoMsg = msg.toString('utf8');
                    console.log('📄 Conteúdo:');
                    console.log(textoMsg);
                    
                    // Salvar no log
                    const logData = {
                        id: this.trapCount,
                        timestamp: timestamp,
                        sender: rinfo.address,
                        port: rinfo.port,
                        size: msg.length,
                        type: 'UDP_TEXT',
                        content: textoMsg
                    };
                    
                    this.logMessage(JSON.stringify(logData, null, 2));
                    
                } catch (e) {
                    // Se não for texto, mostrar como hex
                    console.log('📦 Dados binários (hex):', msg.toString('hex').substring(0, 100) + '...');
                    
                    const logData = {
                        id: this.trapCount,
                        timestamp: timestamp,
                        sender: rinfo.address,
                        port: rinfo.port,
                        size: msg.length,
                        type: 'UDP_BINARY',
                        hex: msg.toString('hex')
                    };
                    
                    this.logMessage(JSON.stringify(logData, null, 2));
                }
            }
            
            // Lógica customizada
            this.processCustomLogic({
                id: this.trapCount,
                sender: rinfo.address,
                timestamp: timestamp,
                size: msg.length
            });
            
            console.log('-----------------------------------');
        });

        server.on('error', (err) => {
            console.error('❌ Erro UDP:', err.message);
            if (err.code === 'EADDRINUSE') {
                console.log('🔧 Porta 162 já em uso. Tentando porta alternativa...');
                this.startAlternativeUDPReceiver();
            }
        });

        server.on('listening', () => {
            const address = server.address();
            console.log(`✅ Receptor UDP ativo em ${address.address}:${address.port}`);
            console.log('⏳ Aguardando traps e dados UDP...\n');
        });

        // Bind na porta 162
        server.bind(162);
    }

    tryParseAsSNMP(buffer) {
        try {
            // Verificar se começa com sequência SNMP típica
            if (buffer.length < 10) return false;
            
            // SNMP geralmente começa com 0x30 (SEQUENCE)
            if (buffer[0] === 0x30) {
                console.log('📋 Possível pacote SNMP detectado!');
                
                // Tentar extrair informações básicas
                const hex = buffer.toString('hex');
                console.log('📦 Dados SNMP (hex):', hex.substring(0, 100) + '...');
                
                // Salvar como SNMP
                const logData = {
                    id: this.trapCount,
                    timestamp: new Date().toISOString(),
                    type: 'SNMP_BINARY',
                    hex: hex,
                    size: buffer.length
                };
                
                this.logMessage(JSON.stringify(logData, null, 2));
                return true;
            }
            
            return false;
        } catch (e) {
            return false;
        }
    }

    startAlternativeUDPReceiver() {
        const dgram = require('dgram');
        const server = dgram.createSocket('udp4');
        
        // Usar porta alternativa
        const altPort = 1162;
        
        server.on('message', (msg, rinfo) => {
            console.log(`\n📨 DADOS na porta ${altPort}:`, msg.toString('utf8').substring(0, 100));
        });
        
        server.bind(altPort);
        console.log(`⚠️  Usando porta alternativa ${altPort} para testes`);
    }

    processTrap(notification) {
        this.trapCount++;
        const timestamp = new Date().toISOString();
        
        console.log(`\n📨 TRAP RECEBIDO #${this.trapCount}`);
        console.log('⏰ Timestamp:', timestamp);
        console.log('🌐 Remetente:', notification.rinfo.address + ':' + notification.rinfo.port);
        console.log('📋 Tipo:', this.getTrapType(notification.pdu.type));
        
        // Processar OIDs recebidos
        const trapData = {
            id: this.trapCount,
            timestamp: timestamp,
            sender: notification.rinfo.address,
            port: notification.rinfo.port,
            type: this.getTrapType(notification.pdu.type),
            oids: []
        };

        if (notification.pdu.varbinds && notification.pdu.varbinds.length > 0) {
            console.log('📊 Dados recebidos:');
            notification.pdu.varbinds.forEach((varbind, index) => {
                const oidInfo = {
                    oid: varbind.oid,
                    type: varbind.type,
                    value: varbind.value
                };
                
                trapData.oids.push(oidInfo);
                console.log(`   ${index + 1}. OID: ${varbind.oid}`);
                console.log(`      Tipo: ${varbind.type}`);
                console.log(`      Valor: ${varbind.value}`);
            });
        }

        // Salvar no log
        this.logMessage(JSON.stringify(trapData, null, 2));
        
        // Aqui você pode adicionar lógica personalizada
        this.processCustomLogic(trapData);
        
        console.log('-----------------------------------');
    }

    processCustomLogic(trapData) {
        // Adicione aqui sua lógica personalizada
        // Exemplos:
        
        // 1. Alertas críticos (verificar se trapData tem oids)
        if (trapData.oids && trapData.oids.some(oid => oid.value && oid.value.toString().includes('critical'))) {
            console.log('🚨 ALERTA CRÍTICO DETECTADO!');
            // Enviar email, webhook, etc.
        }
        
        // 2. Verificar conteúdo do trap (para dados UDP texto)
        if (trapData.content && trapData.content.includes('CPU')) {
            console.log('⚠️  ALERTA DE CPU DETECTADO!');
        }
        
        if (trapData.content && trapData.content.includes('Memory')) {
            console.log('⚠️  ALERTA DE MEMÓRIA DETECTADO!');
        }
        
        if (trapData.content && trapData.content.includes('Disk')) {
            console.log('⚠️  ALERTA DE DISCO DETECTADO!');
        }
        
        // 3. Monitoramento de dispositivos específicos
        if (trapData.sender === '200.10.4.74') {
            console.log('📡 Trap do Windows ASSIST04 recebido');
        }
        
        // 4. Contagem de traps por minuto (exemplo)
        if (this.trapCount % 5 === 0) {
            console.log(`📈 Total de traps recebidos: ${this.trapCount}`);
        }
        
        // 5. Log especial para traps do Windows
        if (trapData.content && trapData.content.includes('ASSIST04')) {
            console.log('🖥️  Trap do computador Windows ASSIST04');
        }
    }

    getTrapType(type) {
        const types = {
            160: 'GetRequest',
            161: 'GetNextRequest', 
            162: 'GetResponse',
            163: 'SetRequest',
            164: 'Trap',
            165: 'GetBulkRequest',
            166: 'InformRequest',
            167: 'SNMPv2-Trap',
            168: 'Report'
        };
        return types[type] || `Desconhecido (${type})`;
    }

    logMessage(message) {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] ${message}\n\n`;
        
        fs.appendFile(this.logFile, logEntry, (err) => {
            if (err) {
                console.error('❌ Erro ao salvar log:', err.message);
            }
        });
    }
}

// Iniciar o receptor
const trapReceiver = new SNMPTrapReceiver();

// Tratamento de sinais para encerramento gracioso
process.on('SIGTERM', () => {
    console.log('\n🛑 Encerrando receptor...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('\n🛑 Encerrando receptor... (Ctrl+C)');
    process.exit(0);
});
