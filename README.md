# DJI_Note

### 无人机数据

<pre>
  
struct SUavInfoIndType10_V2
{
    U8 u8SubCmd;	///< 0x10
    U8 u8ProtoVer;	///< 2
    U16 u16CmdSn;	///< command sequence number inside of device
    /// *******************************
    /// \var U16 u16ValidBitmapFlag
    /// \brief Bitmap flag to indicate data presence.
    /// \see U16,
    /// \details *******************************	\n
    ///   bit0: UAV SN is valid or not.
    ///   bit1: UAV status(from s32UavLongitude to s16AngleYaw, and from bit4 to bit11) is valid or not.
    ///   bit2: Home info(s32HomeLongitude and s32HomeLatitude) is valid or not.
    ///   bit3: UUID is valid or not.
    ///   bit4: .
    ///   bit5: .
    ///   bit6: .
    ///   bit7: .
    ///   bit8: .
    ///   bit9: .
    ///   bit10: .
    ///   bit11: .
    ///   bit12~15: reserved.
    /// *******************************
    U16 u16ValidBitmapFlag;
    char acUavSn[MAX_UAV_SN_LEN];           ///< UAV unique SN code
    S32 s32UavLongitude;                    ///< Unit: 1e-7 rad
    S32 s32UavLatitude;                     ///< Unit: 1e-7 rad
    S16 s16GpsAltitude;                     ///< Unit: m
    S16 s16AirMeterAltitude;                ///< Unit: dm
    S16 s16SpeedX;                          ///< Speed of South-North, Northern is positive direction, Unit: cm/s
    S16 s16SpeedY;                          ///< Speed of West-East, Eastern is positive direction, Unit: cm/s
    S16 s16SpeedZ;                          ///< Speed of Low-High, High is positive direction, Unit: cm/s
    S16 s16AngleYaw;                        ///< Angle of yaw, Unit: 0.01 deg
    U64 u64AppTimeStamp;                    ///< app gps timestamp
    S32 s32AppLongitude;                    ///< app gps longitude 1e-7 rad
    S32 s32AppLatitude;                     ///< app gps Latitude 1e-7 rad
    S32 s32HomeLongitude;                   ///< home Longitude 1e-7 rad
    S32 s32HomeLatitude;                    ///< home Latitude 1e-7 rad
    U8 u8ProductType;                       ///< Uav type
    U8 u8UuidLen;                           ///< Uuid len
    U8 au8Uuid[MAX_UUID_LEN];               ///< Uuid text
};
                                                 
</pre>

### 主机数据

<pre>

struct SDeviceStatusInd
{
    U8 u8ProtoVer;                          ///<  1
    char acDeviceSn[MAX_DEVICE_SN_LEN];
    U32 u32RunTime;                         ///< Runtime Seconds from start up
    S32 s32Longitude;                    	///<  Unit: 1e7 degree
    S32 s32Latitude;                     	///<  Unit: 1e7 degree
    UDevStatus udsDevStatus;                ///< 设备状态
    ULbStatus udsLbStatus;                  ///< LB模块通信状态
    UWifiStatus udsWifiStatus;              ///< Wifi模块通信状态
    USdrStatus udsSdrStatus;                ///< SDR模块通信状态
    U8 u8Soc;                               ///< 剩余电量
    U16 u16TotalInCurrent;                  ///< 总输入电流*100
    U16 u16AntCurrent;                      ///< 天线电流*100
    U16 u16TotalInVoltage;                  ///< 总输入电压*100
    U16 u16GpsBusVoltage;					///< GPS总线电压*100
    S16 u16PcbTemperture;					///< PCB板温度*100
    U16 u16HubSupplyVoltage;				///< HUB供电电压*100
    U16 u16SdrTxVoltage;					///< SDR TX电压*100
    U16 u16Svs5V;                           ///< 5V电源监控电压*100
    U16 u16MainBoardLbVol;					///< 主RF板LB电压*100
    U16 u16MainBoardWifiVol;				///< 主RF板WIFI电压*100
    U16 u16MainBoardSdrVol;					///< 主RF板SDR电压*100
    U16 u16MainBoardAnt3V3Vol;				///< 主RF板3V3电压*100
    U16 u16MainBoardLbCur;					///< 主RF板LB电流*100
    U16 u16MainBoardWifiCur;				///< 主RF板WIFI电流*100
    U16 u16MainBoardSdrCur;					///< 主RF板SDR电流*100
    U16 u16MainBoardAnt3V3Cur;				///< 主RF板3V3电流*100
    U16 u16MinorBoardLbVol;					///< 副RF板LB电压*100
    U16 u16MinorBoardWifiVol;				///< 副RF板WIFI电压*100
    U16 u16MinorBoardSdrVol;				///< 副RF板SDR电压*100
    U16 u16MinorBoardAnt3V3Vol;				///< 副RF板3V3电压*100
    U16 u16MinorBoardLbCur;					///< 副RF板LB电流*100
    U16 u16MinorBoardWifiCur;				///< 副RF板WIFI电流*100
    U16 u16MinorBoardSdrCur;				///< 副RF板SDR电流*100
    U16 u16MinorBoardAnt3V3Cur;             ///< 副RF板3V3电流*100
    U8 u8GpsSatellite;                      ///< GPS搜星数量
};
  
  
</pre>


### 校验码

crc8：

<pre>

 def calc_pkt55_hdr_checksum(seed, packet, plength):
    arr_2A103 = [
      0x00, 0x5E, 0xBC, 0xE2, 0x61, 0x3F, 0xDD, 0x83, 0xC2, 0x9C, 0x7E, 0x20, 0xA3, 0xFD, 0x1F, 0x41,      0x9D, 0xC3, 0x21, 0x7F, 0xFC, 0xA2, 0x40, 0x1E, 0x5F, 0x01, 0xE3, 0xBD, 0x3E, 0x60, 0x82, 0xDC,      0x23, 0x7D, 0x9F, 0xC1, 0x42, 0x1C, 0xFE, 0xA0, 0xE1, 0xBF, 0x5D, 0x03, 0x80, 0xDE, 0x3C, 0x62,      0xBE, 0xE0, 0x02, 0x5C, 0xDF, 0x81, 0x63, 0x3D, 0x7C, 0x22, 0xC0, 0x9E, 0x1D, 0x43, 0xA1, 0xFF,
      0x46, 0x18, 0xFA, 0xA4, 0x27, 0x79, 0x9B, 0xC5, 0x84, 0xDA, 0x38, 0x66, 0xE5, 0xBB, 0x59, 0x07,      0xDB, 0x85, 0x67, 0x39, 0xBA, 0xE4, 0x06, 0x58, 0x19, 0x47, 0xA5, 0xFB, 0x78, 0x26, 0xC4, 0x9A,      0x65, 0x3B, 0xD9, 0x87, 0x04, 0x5A, 0xB8, 0xE6, 0xA7, 0xF9, 0x1B, 0x45, 0xC6, 0x98, 0x7A, 0x24,      0xF8, 0xA6, 0x44, 0x1A, 0x99, 0xC7, 0x25, 0x7B, 0x3A, 0x64, 0x86, 0xD8, 0x5B, 0x05, 0xE7, 0xB9,
      0x8C, 0xD2, 0x30, 0x6E, 0xED, 0xB3, 0x51, 0x0F, 0x4E, 0x10, 0xF2, 0xAC, 0x2F, 0x71, 0x93, 0xCD,      0x11, 0x4F, 0xAD, 0xF3, 0x70, 0x2E, 0xCC, 0x92, 0xD3, 0x8D, 0x6F, 0x31, 0xB2, 0xEC, 0x0E, 0x50,      0xAF, 0xF1, 0x13, 0x4D, 0xCE, 0x90, 0x72, 0x2C, 0x6D, 0x33, 0xD1, 0x8F, 0x0C, 0x52, 0xB0, 0xEE,      0x32, 0x6C, 0x8E, 0xD0, 0x53, 0x0D, 0xEF, 0xB1, 0xF0, 0xAE, 0x4C, 0x12, 0x91, 0xCF, 0x2D, 0x73,
      0xCA, 0x94, 0x76, 0x28, 0xAB, 0xF5, 0x17, 0x49, 0x08, 0x56, 0xB4, 0xEA, 0x69, 0x37, 0xD5, 0x8B,      0x57, 0x09, 0xEB, 0xB5, 0x36, 0x68, 0x8A, 0xD4, 0x95, 0xCB, 0x29, 0x77, 0xF4, 0xAA, 0x48, 0x16,      0xE9, 0xB7, 0x55, 0x0B, 0x88, 0xD6, 0x34, 0x6A, 0x2B, 0x75, 0x97, 0xC9, 0x4A, 0x14, 0xF6, 0xA8,      0x74, 0x2A, 0xC8, 0x96, 0x15, 0x4B, 0xA9, 0xF7, 0xB6, 0xE8, 0x0A, 0x54, 0xD7, 0x89, 0x6B, 0x35,
    ]

    chksum = seed
    for i in range(0, plength):
        chksum = arr_2A103[((packet[i] ^ chksum) & 0xFF)]
    return chksum

head = [0x55, 0x11,0x04]  # 92
head = [0x55, 0x64,0x04]  # db
head = [0x55, 0x61,0x04]  # 24
head = [0x55, 0x96,0x04]  # d3
head = [0x55, 0x6d,0x04]  # 69

crc8 = calc_pkt55_hdr_checksum(0x77, head,3)
print(hex(crc8)) 
  
</pre>

crc16:

<pre>

/*
**   const variable define  
*/ 
const unsigned short wCRC_Table[256] = ....

const unsigned short CRC_INIT = ....

/*
**  Descriptions: CRC16 checksum function                                  
**  Input:        Data to check,Stream length, initialized checksum                     
**  Output:       CRC checksum                                                          
*/ 
unsigned short check_crc16_sum(unsigned char *pchMessage,unsigned int dwLength,unsigned short wCRC) 
{  
    unsigned char chData; 
	if (pchMessage == 0) 
    { 
        return 0xFFFF; 
    }     
     
    while(dwLength--) 
    { 
        chData = *pchMessage++;
        (wCRC) = ((unsigned short)(wCRC) >> 8)  ^ wCRC_Table[((unsigned short)(wCRC) ^ (unsigned short)(chData)) & 0x00ff];
    } 
     
    return wCRC; 
} 
 
/*
**  Descriptions: CRC16 Verify function                                  
**  Input:        Data to Verify,Stream length = Data + checksum                    
**  Output:       True or False (CRC Verify Result)                                                        
*/                  
//CRC 的验证方法也可以是看append后的字节流经过CRC运算后结果是否为零来判断
unsigned int check_verify_crc16_sum(unsigned char *pchMessage, unsigned int dwLength) 
{ 
    unsigned short wExpected = 0; 
     
    if ((pchMessage == 0) || (dwLength <= 2)) 
    { 
        return 0; 
    } 
    wExpected = check_crc16_sum( pchMessage, dwLength - 2, CRC_INIT); 
     
    return (wExpected & 0xff) == pchMessage[dwLength - 2] && 
		((wExpected >> 8) & 0xff) == pchMessage[dwLength - 1]; 
}  

/*
**  Descriptions: append CRC16 to the end of data                                
**  Input:        Data to CRC and append,Stream length = Data + checksum                    
**  Output:       True or False (CRC Verify Result)                                                        
*/ 
void check_append_crc16_sum(unsigned char* pchMessage,unsigned int dwLength) 
{  
    unsigned short wCRC = 0; 
     
    if ((pchMessage == 0) || (dwLength <= 2)) 
    { 
        return; 
    } 
    wCRC = check_crc16_sum( (unsigned char *)pchMessage, dwLength-2, CRC_INIT ); 
     
    pchMessage[dwLength-2] = (unsigned char)(wCRC & 0x00ff); 
    pchMessage[dwLength-1] = (unsigned char)((wCRC >> 8)& 0x00ff); 
}



#include <stdio.h>
#include <vector>
#include <string>
#include <string.h>

std::vector<unsigned char> char2hexvec(const char* msg, unsigned int len)
{
    int hex_len = len / 2;

    std::vector<unsigned char> buf(hex_len);

    for(int i=0;i<hex_len; i ++){
        std::string tmp(msg + 2*i, 2);
        buf[i] = std::stoi( tmp, 0, 16);
    }

    return buf;
}


int main()
{
    
    std::vector<unsigned char> buf= {0x55, 0x0e, 0x04, 0x66, 0x0a, 0x0d , 0x11 , 0x27, 0x40, 0x09, 0xc0, 0x01     , 0x44, 0x1e};
    short crc = check_crc16_sum(buf.data(), buf.size()-2, CRC_INIT);
    printf("%x\n", crc & 0xffff);


    const char msg[] = "551d04df0a0d" "13" "274009c0040e" "3051524445395530303130303636" "7fc2";
    buf = char2hexvec(msg, strlen(msg) - 4);

    crc = check_crc16_sum(buf.data(), buf.size(), CRC_INIT);
    printf("%x\n", crc & 0xffff);

    return 0;
}
  
</pre>
