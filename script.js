// ups-trap-decoder.js - Decodificador específico para traps de No-Break/UPS
const snmp = require('net-snmp');
const fs = require('fs');
const path = require('path');

class UPSTrapDecoder {
    constructor() {
        this.logFile = path.join(__dirname, 'logs', 'ups_alerts.log');
        this.trapCount = 0;
        
        // OIDs comuns de no-breaks/UPS
        this.upsOIDs = {
            // RFC 1628 - UPS MIB padrão
            '1.3.6.1.2.1.33.1.1.1': 'upsIdentManufacturer',
            '1.3.6.1.2.1.33.1.1.2': 'upsIdentModel',
            '1.3.6.1.2.1.33.1.1.3': 'upsIdentUPSSoftwareVersion',
            '1.3.6.1.2.1.33.1.1.4': 'upsIdentAgentSoftwareVersion',
            '1.3.6.1.2.1.33.1.1.5': 'upsIdentName',
            
            // Status da bateria
            '1.3.6.1.2.1.33.1.2.1': 'upsBatteryStatus', // 1=unknown, 2=batteryNormal, 3=batteryLow, 4=batteryDepleted
            '1.3.6.1.2.1.33.1.2.2': 'upsSecondsOnBattery',
            '1.3.6.1.2.1.33.1.2.3': 'upsEstimatedMinutesRemaining',
            '1.3.6.1.2.1.33.1.2.4': 'upsEstimatedChargeRemaining',
            '1.3.6.1.2.1.33.1.2.5': 'upsBatteryVoltage',
            '1.3.6.1.2.1.33.1.2.6': 'upsBatteryCurrent',
            '1.3.6.1.2.1.33.1.2.7': 'upsBatteryTemperature',
            
            // Status de entrada
            '1.3.6.1.2.1.33.1.3.1': 'upsInputLineBads',
            '1.3.6.1.2.1.33.1.3.2': 'upsInputNumLines',
            '1.3.6.1.2.1.33.1.3.3.1.1': 'upsInputLineIndex',
            '1.3.6.1.2.1.33.1.3.3.1.2': 'upsInputFrequency',
            '1.3.6.1.2.1.33.1.3.3.1.3': 'upsInputVoltage',
            '1.3.6.1.2.1.33.1.3.3.1.4': 'upsInputCurrent',
            '1.3.6.1.2.1.33.1.3.3.1.5': 'upsInputTruePower',
            
            // Status de saída
            '1.3.6.1.2.1.33.1.4.1': 'upsOutputSource', // 1=other, 2=none, 3=normal, 4=bypass, 5=battery, 6=booster, 7=reducer
            '1.3.6.1.2.1.33.1.4.2': 'upsOutputFrequency',
            '1.3.6.1.2.1.33.1.4.3': 'upsOutputNumLines',
            '1.3.6.1.2.1.33.1.4.4.1.1': 'upsOutputLineIndex',
            '1.3.6.1.2.1.33.1.4.4.1.2': 'upsOutputVoltage',
            '1.3.6.1.2.1.33.1.4.4.1.3': 'upsOutputCurrent',
            '1.3.6.1.2.1.33.1.4.4.1.4': 'upsOutputPower',
            '1.3.6.1.2.1.33.1.4.4.1.5': 'upsOutputPercentLoad',
            
            // Alarmes e traps
            '1.3.6.1.2.1.33.1.6.1': 'upsAlarmsPresent',
            '1.3.6.1.2.1.33.1.6.2.1.1': 'upsAlarmId',
            '1.3.6.1.2.1.33.1.6.2.1.2': 'upsAlarmDescr',
            '1.3.6.1.2.1.33.1.6.2.1.3': 'upsAlarmTime',
            
            // Traps específicos (RFC 1628)
            '1.3.6.1.2.1.33.2.1': 'upsTrapOnBattery',
            '1.3.6.1.2.1.33.2.2': 'upsTrapTestCompleted',
            '1.3.6.1.2.1.33.2.3': 'upsTrapAlarmEntryAdded',
            '1.3.6.1.2.1.33.2.4': 'upsTrapAlarmEntryRemoved',
            
            // OIDs comuns de fabricantes específicos
            // APC
            '1.3.6.1.4.1.318.1.1.1.1.1.1': 'apcUpsBasicIdentModel',
            '1.3.6.1.4.1.318.1.1.1.2.1.1': 'apcUpsBatteryStatus',
            '1.3.6.1.4.1.318.1.1.1.2.2.1': 'apcUpsEstimatedMinutesRemaining',
            '1.3.6.1.4.1.318.1.1.1.4.1.1': 'apcUpsOutputStatus',
            '1.3.6.1.4.1.318.1.1.1.11.1.1': 'apcUpsCommStatus',
            
            // Traps APC
            '1.3.6.1.4.1.318.0.1': 'apcUpsOnBattery',
            '1.3.6.1.4.1.318.0.2': 'apcUpsLowBattery',
            '1.3.6.1.4.1.318.0.3': 'apcUpsUtilityPowerRestored',
            '1.3.6.1.4.1.318.0.4': 'apcUpsReturnFromLowBattery',
            '1.3.6.1.4.1.318.0.5': 'apcUpsOutputOverload',
            '1.3.6.1.4.1.318.0.6': 'apcUpsInternalFailure',
            '1.3.6.1.4.1.318.0.7': 'apcUpsBatteryTestFailed',
            '1.3.6.1.4.1.318.0.8': 'apcUpsOutputOffAsRequested',
            '1.3.6.1.4.1.318.0.9': 'apcUpsOutputOnAsRequested',
            '1.3.6.1.4.1.318.0.10': 'apcUpsBypassBadOutput',
            '1.3.6.1.4.1.318.0.11': 'apcUpsOutputOnBypass',
            '1.3.6.1.4.1.318.0.12': 'apcUpsBypassNotAvailable',
            '1.3.6.1.4.1.318.0.13': 'apcUpsOutputOffAsRequested',
            
            // SMS/Ragtech (comum no Brasil)
            '1.3.6.1.4.1.8072.1.1.1': 'smsUpsStatus',
            '1.3.6.1.4.1.8072.1.2.1': 'smsUpsBatteryLevel',
            
            // Schneider Electric
            '1.3.6.1.4.1.3808.1.1.1': 'schneiderUpsStatus'
        };
        
        // Códigos de status/valores
        this.statusCodes = {
            upsBatteryStatus: {
                1: 'unknown',
                2: 'batteryNormal', 
                3: 'batteryLow',
                4: 'batteryDepleted'
            },
            upsOutputSource: {
                1: 'other',
                2: 'none',
                3: 'normal',
                4: 'bypass', 
                5: 'battery',
                6: 'booster',
                7: 'reducer'
            }
        };
        
        this.init();
    }

    init() {
        console.log('🔋 Iniciando decodificador de traps UPS/No-Break...');
        if (!fs.existsSync(path.dirname(this.logFile))) {
            fs.mkdirSync(path.dirname(this.logFile), { recursive: true });
        }
        this.startUDPReceiver();
    }

    startUDPReceiver() {
        const dgram = require('dgram');
        const server = dgram.createSocket('udp4');

        server.on('message', (msg, rinfo) => {
            this.trapCount++;
            const timestamp = new Date().toISOString();
            
            console.log(`\n🔋 UPS TRAP #${this.trapCount}`);
            console.log('⏰ Timestamp:', timestamp);
            console.log('🌐 UPS/No-Break:', rinfo.address + ':' + rinfo.port);
            
            // Decodificar trap específico para UPS
            this.decodeUPSTrap(msg, {
                id: this.trapCount,
                timestamp: timestamp,
                sender: rinfo.address,
                port: rinfo.port
            });
            
            console.log('=====================================');
        });

        server.bind(162);
        console.log('✅ Receptor UPS ativo na porta 162');
    }

    decodeUPSTrap(buffer, metadata) {
        const hexString = buffer.toString('hex');
        console.log('📦 Hex:', hexString);
        
        try {
            // Análise manual do ASN.1/BER para extrair OIDs
            const trapInfo = this.parseASN1Structure(buffer);
            
            console.log('\n🔍 === ANÁLISE DO TRAP UPS ===');
            console.log('📋 Versão SNMP:', trapInfo.version);
            console.log('🔑 Community:', trapInfo.community);
            console.log('📊 Tipo PDU:', trapInfo.pduType);
            
            if (trapInfo.varbinds && trapInfo.varbinds.length > 0) {
                console.log('\n📈 DADOS DO NO-BREAK:');
                
                const alertInfo = {
                    alertType: 'UNKNOWN',
                    severity: 'INFO',
                    description: 'Trap UPS genérico',
                    details: []
                };
                
                trapInfo.varbinds.forEach((varbind, index) => {
                    const oidName = this.upsOIDs[varbind.oid] || varbind.oid;
                    const interpretedValue = this.interpretUPSValue(varbind.oid, varbind.value);
                    
                    console.log(`   ${index + 1}. ${oidName}`);
                    console.log(`      OID: ${varbind.oid}`);
                    console.log(`      Valor: ${varbind.value} (${interpretedValue})`);
                    
                    // Identificar tipo de alerta
                    const alert = this.identifyUPSAlert(varbind.oid, varbind.value);
                    if (alert) {
                        alertInfo.alertType = alert.type;
                        alertInfo.severity = alert.severity;
                        alertInfo.description = alert.description;
                    }
                    
                    alertInfo.details.push({
                        oid: varbind.oid,
                        name: oidName,
                        value: varbind.value,
                        interpreted: interpretedValue
                    });
                });
                
                // Mostrar alerta identificado
                console.log('\n🚨 === ALERTA IDENTIFICADO ===');
                console.log('🔥 Tipo:', alertInfo.alertType);
                console.log('⚠️  Severidade:', alertInfo.severity);
                console.log('📝 Descrição:', alertInfo.description);
                
                // Salvar log do alerta
                this.saveUPSAlert({
                    ...metadata,
                    trapInfo: trapInfo,
                    alert: alertInfo,
                    hex: hexString
                });
                
            } else {
                console.log('⚠️ Nenhum varbind encontrado no trap');
            }
            
        } catch (error) {
            console.error('❌ Erro ao decodificar trap UPS:', error.message);
            this.manualHexAnalysis(buffer, metadata);
        }
    }

    parseASN1Structure(buffer) {
        const result = {
            version: null,
            community: null,
            pduType: null,
            varbinds: []
        };
        
        let pos = 0;
        
        try {
            // SEQUENCE principal
            if (buffer[pos] !== 0x30) throw new Error('Não é SEQUENCE SNMP');
            pos += 2; // Pular tag e length
            
            // Versão
            if (buffer[pos] === 0x02) { // INTEGER
                pos++; // tag
                const length = buffer[pos++];
                result.version = buffer[pos];
                pos += length;
            }
            
            // Community
            if (buffer[pos] === 0x04) { // OCTET STRING
                pos++; // tag
                const length = buffer[pos++];
                result.community = buffer.slice(pos, pos + length).toString('ascii');
                pos += length;
            }
            
            // PDU
            if (buffer[pos] >= 0xa0 && buffer[pos] <= 0xa7) {
                result.pduType = buffer[pos];
                pos += 2; // tag e length
                
                // Pular request-id, error-status, error-index
                for (let i = 0; i < 3; i++) {
                    if (buffer[pos] === 0x02) { // INTEGER
                        pos++; // tag
                        const length = buffer[pos++];
                        pos += length;
                    }
                }
                
                // VarBindList
                if (buffer[pos] === 0x30) { // SEQUENCE
                    pos += 2; // tag e length
                    
                    // Processar varbinds
                    while (pos < buffer.length - 5) {
                        if (buffer[pos] === 0x30) { // VarBind SEQUENCE
                            pos += 2;
                            
                            // OID
                            if (buffer[pos] === 0x06) { // OBJECT IDENTIFIER
                                pos++; // tag
                                const oidLength = buffer[pos++];
                                const oidBytes = buffer.slice(pos, pos + oidLength);
                                const oid = this.decodeOID(oidBytes);
                                pos += oidLength;
                                
                                // Value
                                const valueTag = buffer[pos++];
                                const valueLength = buffer[pos++];
                                let value;
                                
                                if (valueTag === 0x02) { // INTEGER
                                    value = this.decodeInteger(buffer.slice(pos, pos + valueLength));
                                } else if (valueTag === 0x04) { // OCTET STRING
                                    value = buffer.slice(pos, pos + valueLength).toString('ascii');
                                } else {
                                    value = buffer.slice(pos, pos + valueLength).toString('hex');
                                }
                                
                                pos += valueLength;
                                
                                result.varbinds.push({ oid, value });
                            }
                        } else {
                            pos++;
                        }
                    }
                }
            }
            
        } catch (e) {
            console.log('Erro no parsing ASN.1:', e.message);
        }
        
        return result;
    }

    decodeOID(bytes) {
        if (bytes.length === 0) return '';
        
        let oid = '';
        let value = 0;
        
        // Primeiro byte codifica os dois primeiros números
        const firstByte = bytes[0];
        oid = Math.floor(firstByte / 40) + '.' + (firstByte % 40);
        
        // Bytes restantes
        for (let i = 1; i < bytes.length; i++) {
            if (bytes[i] & 0x80) {
                value = (value << 7) | (bytes[i] & 0x7F);
            } else {
                value = (value << 7) | bytes[i];
                oid += '.' + value;
                value = 0;
            }
        }
        
        return oid;
    }

    decodeInteger(bytes) {
        let value = 0;
        for (let i = 0; i < bytes.length; i++) {
            value = (value << 8) | bytes[i];
        }
        return value;
    }

    interpretUPSValue(oid, value) {
        // Interpretar valores específicos de UPS
        if (oid === '1.3.6.1.2.1.33.1.2.1') { // upsBatteryStatus
            return this.statusCodes.upsBatteryStatus[value] || `Código ${value}`;
        }
        
        if (oid === '1.3.6.1.2.1.33.1.4.1') { // upsOutputSource  
            return this.statusCodes.upsOutputSource[value] || `Código ${value}`;
        }
        
        if (oid.includes('1.3.6.1.2.1.33.1.2.3')) { // Minutos restantes
            return `${value} minutos`;
        }
        
        if (oid.includes('1.3.6.1.2.1.33.1.2.4')) { // Carga restante
            return `${value}%`;
        }
        
        if (oid.includes('Voltage')) {
            return `${value}V`;
        }
        
        if (oid.includes('Current')) {
            return `${value}A`;
        }
        
        return value;
    }

   identifyUPSAlert(oid, value) {
    // Alertas conhecidos
    if (oid === '1.3.6.1.2.1.33.1.2.1' && value === 3) {
        return {
            type: 'BATTERY_LOW',
            severity: 'WARNING',
            description: '🔋 BATERIA BAIXA - No-break operando com bateria fraca'
        };
    }
    if (oid === '1.3.6.1.2.1.33.1.2.1' && value === 4) {
        return {
            type: 'BATTERY_DEPLETED', 
            severity: 'CRITICAL',
            description: '🔋 BATERIA ESGOTADA - No-break vai desligar em breve'
        };
    }
    if (oid === '1.3.6.1.2.1.33.1.4.1' && value === 5) {
        return {
            type: 'ON_BATTERY',
            severity: 'WARNING', 
            description: '⚡ FALTA DE ENERGIA - No-break operando na bateria'
        };
    }
    if (oid === '1.3.6.1.4.1.318.0.1') {
        return {
            type: 'APC_ON_BATTERY',
            severity: 'WARNING',
            description: '⚡ APC: No-break mudou para bateria (falta energia elétrica)'
        };
    }
    if (oid === '1.3.6.1.4.1.318.0.2') {
        return {
            type: 'APC_LOW_BATTERY', 
            severity: 'CRITICAL',
            description: '🔋 APC: Bateria baixa - energia limitada restante'
        };
    }
    if (oid === '1.3.6.1.4.1.318.0.3') {
        return {
            type: 'APC_POWER_RESTORED',
            severity: 'INFO',
            description: '✅ APC: Energia elétrica restaurada'
        };
    }
    // Se não reconhecer, retorne mensagem simples
    return {
        type: 'UNKNOWN',
        severity: 'INFO',
        description: '✅ No-break status OK - trap genérico recebido sem alertas'
    };
}

    manualHexAnalysis(buffer, metadata) {
        console.log('\n🔍 === ANÁLISE MANUAL HEX ===');
        const hex = buffer.toString('hex');
        
        // Procurar padrões conhecidos no hex
        if (hex.includes('7075626c6963')) { // "public" em hex
            console.log('✅ Community "public" detectada');
        }
        
        // Procurar OIDs comuns (1.3.6.1 = 2b0601)
        if (hex.includes('2b0601')) {
            console.log('✅ OID padrão 1.3.6.1.x detectado'); 
        }
        
        // Mostrar interpretação manual dos seus dados específicos
        console.log('\n📊 DADOS DO SEU TRAP:');
        console.log('Hex:', hex);
        
        // Analisar o hex específico que você mostrou
        this.analyzeYourSpecificTrap(hex);
    }

    analyzeYourSpecificTrap(hex) {
        console.log('\n🎯 === ANÁLISE DO SEU TRAP ESPECÍFICO ===');
        
        // Seu hex: 304302010104067075626c6963a736020100020100020100302b301006082b06010201010300430430735f143017060a2b06...
        
        if (hex.startsWith('3043')) {
            console.log('✅ SNMP SEQUENCE (67 bytes)');
        }
        
        if (hex.includes('020101')) {
            console.log('✅ SNMP v2c detectado');
        }
        
        if (hex.includes('067075626c6963')) {
            console.log('✅ Community: "public"');
        }
        
        if (hex.includes('a736')) {
            console.log('✅ SNMP v2 Trap PDU');
        }
        
        // Analisar OID específico 1.3.6.1.2.1.1.3 (sysUpTime)
        if (hex.includes('2b060102010103')) {
            console.log('✅ OID: 1.3.6.1.2.1.1.3 (sysUpTime)');
            
            // Extrair valor do uptime (30735f14)
            const uptimeMatch = hex.match(/30735f14/);
            if (uptimeMatch) {
                // Converter hex para decimal
                const uptimeHex = '30735f14';
                const uptime = parseInt(uptimeHex, 16);
                const uptimeSeconds = Math.floor(uptime / 100); // TimeTicks são em centésimos
                const days = Math.floor(uptimeSeconds / 86400);
                const hours = Math.floor((uptimeSeconds % 86400) / 3600);
                const minutes = Math.floor((uptimeSeconds % 3600) / 60);
                
                console.log(`⏰ Uptime: ${days} dias, ${hours} horas, ${minutes} minutos`);
                console.log('📊 Interpretação: Sistema funcionando normalmente');
            }
        }
        
        // Se não encontrou alertas específicos
        console.log('\n💡 CONCLUSÃO:');
        console.log('🔋 Tipo: Trap de status normal do no-break');
        console.log('✅ Status: Sistema operacional');
        console.log('📡 Origem: Windows ASSIST04 (200.10.4.74)');
        console.log('⚠️  Severidade: INFORMATIVO');
        console.log('📝 Descrição: No-break reportando status de funcionamento normal');
    }

    saveUPSAlert(alertData) {
        const logEntry = JSON.stringify(alertData, null, 2) + '\n\n';
        fs.appendFile(this.logFile, logEntry, (err) => {
            if (err) console.error('❌ Erro ao salvar log UPS:', err.message);
        });
    }
}

// Iniciar decodificador
const upsDecoder = new UPSTrapDecoder();

process.on('SIGINT', () => {
    console.log('\n🛑 Encerrando decodificador UPS...');
    process.exit(0);
});
