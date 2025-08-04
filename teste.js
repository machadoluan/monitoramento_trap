// Adicione estas funções ao seu script para decodificar SNMP

decodeSNMPTrap(hexString) {
    try {
        console.log('🔍 DECODIFICANDO TRAP SNMP:');
        const buffer = Buffer.from(hexString, 'hex');
        
        // Análise básica do pacote SNMP
        let pos = 0;
        
        // Verificar se é SEQUENCE (0x30)
        if (buffer[pos] === 0x30) {
            console.log('✅ Formato SNMP válido (SEQUENCE)');
            pos++;
            
            // Pular length byte
            const length = buffer[pos];
            pos++;
            console.log('📏 Tamanho do pacote:', length);
            
            // Version (INTEGER)
            if (buffer[pos] === 0x02) {
                pos++;
                const verLen = buffer[pos];
                pos++;
                const version = buffer[pos];
                pos++;
                
                let versionStr = 'Desconhecida';
                switch(version) {
                    case 0: versionStr = 'SNMPv1'; break;
                    case 1: versionStr = 'SNMPv2c'; break;
                    case 3: versionStr = 'SNMPv3'; break;
                }
                console.log('🏷️  Versão SNMP:', versionStr, `(${version})`);
            }
            
            // Community String (OCTET STRING)
            if (buffer[pos] === 0x04) {
                pos++;
                const commLen = buffer[pos];
                pos++;
                const community = buffer.slice(pos, pos + commLen).toString('ascii');
                pos += commLen;
                console.log('🔐 Community:', community);
            }
            
            // PDU Type (context-specific)
            const pduType = buffer[pos];
            console.log('📋 PDU Type:', '0x' + pduType.toString(16));
            
            let pduTypeStr = 'Desconhecido';
            switch(pduType) {
                case 0xa0: pduTypeStr = 'GetRequest'; break;
                case 0xa1: pduTypeStr = 'GetNextRequest'; break;
                case 0xa2: pduTypeStr = 'GetResponse'; break;
                case 0xa3: pduTypeStr = 'SetRequest'; break;
                case 0xa4: pduTypeStr = 'SNMPv1 Trap'; break;
                case 0xa5: pduTypeStr = 'GetBulkRequest'; break;
                case 0xa6: pduTypeStr = 'InformRequest'; break;
                case 0xa7: pduTypeStr = 'SNMPv2 Trap'; break;
            }
            console.log('📨 Tipo do Trap:', pduTypeStr);
            
            // Se for trap v1 (0xa4), extrair mais detalhes
            if (pduType === 0xa4) {
                this.decodeV1Trap(buffer, pos);
            }
            // Se for trap v2c (0xa7), extrair mais detalhes  
            else if (pduType === 0xa7) {
                this.decodeV2Trap(buffer, pos);
            }
            
        } else {
            console.log('❌ Formato SNMP inválido');
        }
        
    } catch (error) {
        console.log('❌ Erro na decodificação:', error.message);
        console.log('🔍 Primeiros 20 bytes (hex):', hexString.substring(0, 40));
    }
}

decodeV1Trap(buffer, startPos) {
    console.log('🔍 Decodificando SNMPv1 Trap...');
    
    try {
        let pos = startPos + 1; // Pular PDU type
        const pduLen = buffer[pos];
        pos++;
        
        console.log('📏 Tamanho do PDU:', pduLen);
        
        // Enterprise OID (OBJECT IDENTIFIER)
        if (buffer[pos] === 0x06) {
            pos++;
            const oidLen = buffer[pos];
            pos++;
            
            const oidBytes = buffer.slice(pos, pos + oidLen);
            const oid = this.decodeOID(oidBytes);
            pos += oidLen;
            
            console.log('🏢 Enterprise OID:', oid);
        }
        
        // Agent Address (IP ADDRESS - application type 0)
        if (buffer[pos] === 0x40) {
            pos++;
            const ipLen = buffer[pos];
            pos++;
            
            if (ipLen === 4) {
                const ip = Array.from(buffer.slice(pos, pos + 4)).join('.');
                pos += 4;
                console.log('🌐 Agent Address:', ip);
            }
        }
        
        // Generic Trap (INTEGER)
        if (buffer[pos] === 0x02) {
            pos++;
            const genLen = buffer[pos];
            pos++;
            const genericTrap = buffer[pos];
            pos++;
            
            const trapTypes = {
                0: 'coldStart',
                1: 'warmStart', 
                2: 'linkDown',
                3: 'linkUp',
                4: 'authenticationFailure',
                5: 'egpNeighborLoss',
                6: 'enterpriseSpecific'
            };
            
            console.log('⚡ Generic Trap:', trapTypes[genericTrap] || `Desconhecido (${genericTrap})`);
        }
        
        // Specific Trap (INTEGER)
        if (buffer[pos] === 0x02) {
            pos++;
            const specLen = buffer[pos];
            pos++;
            const specificTrap = buffer[pos];
            pos++;
            
            console.log('🎯 Specific Trap:', specificTrap);
        }
        
        // Timestamp (TimeTicks)
        if (buffer[pos] === 0x43) {
            pos++;
            const timeLen = buffer[pos];
            pos++;
            
            let timestamp = 0;
            for (let i = 0; i < timeLen; i++) {
                timestamp = (timestamp << 8) + buffer[pos + i];
            }
            pos += timeLen;
            
            const seconds = timestamp / 100;
            console.log('⏰ Timestamp:', timestamp, `(${seconds} segundos)`);
        }
        
        console.log('✅ SNMPv1 Trap decodificado com sucesso');
        
    } catch (error) {
        console.log('❌ Erro na decodificação v1:', error.message);
    }
}

decodeOID(oidBytes) {
    try {
        if (oidBytes.length === 0) return '';
        
        const oid = [];
        
        // Primeiro byte contém os dois primeiros sub-identificadores
        const firstByte = oidBytes[0];
        oid.push(Math.floor(firstByte / 40));
        oid.push(firstByte % 40);
        
        // Processar bytes restantes
        let pos = 1;
        while (pos < oidBytes.length) {
            let value = 0;
            let byte;
            
            do {
                byte = oidBytes[pos];
                value = (value * 128) + (byte & 0x7F);
                pos++;
            } while ((byte & 0x80) !== 0 && pos < oidBytes.length);
            
            oid.push(value);
        }
        
        return oid.join('.');
        
    } catch (error) {
        return 'OID inválido';
    }
}

// Adicione esta chamada na função tryParseAsSNMP:
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
            
            // NOVA LINHA: Decodificar o trap
            this.decodeSNMPTrap(hex);
            
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
