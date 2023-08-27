package com.ahuaman.akamaibypass

import java.security.Key
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class SensorDataKotlin {
    var mDeviceInfo = DeviceInfo()
    var aesKey: SecretKey? = null
    var hmacKey: SecretKey? = null
    var aesKeyEncrypted: String? = null
    var hmacKeyEncrypted: String? = null

    init {
        uptime = (getRandomNumber(0, 12) * 36).toLong()
    }

    val sensorData: String
        get() {
            mDeviceInfo = DeviceInfo()
            val model = mDeviceInfo.model
            val androidVersion = mDeviceInfo.androidVersion
            val brand = mDeviceInfo.brand
            val SDKINT = mDeviceInfo.SDKINT
            val manufacturer = mDeviceInfo.manufacturer
            val cputype = mDeviceInfo.cputype
            val stringBuilder6 = StringBuilder()
            stringBuilder6.append("3.2.2-1,2,-94,-100,").append("-1,uaend,-1,")
                .append(DeviceInfo.randomScreenSize()).append(",1,100,1,en,")
                .append(androidVersion).append(",0,").append(model).append(",")
                .append(manufacturer).append(",").append(cputype).append(",-1,")
                .append("com.clairmail.fth").append(",-1,-1,").append(
                    UUID.randomUUID()
                ).append(",-1,1,0,REL,").append(
                    getRandomNumber(0, 999999999)
                ).append(",").append(SDKINT).append(",").append(brand).append(",").append(model)
                .append(",release-keys,user,").append(brand).append(",").append(brand)
                .append("-user/").append(androidVersion).append("/").append(
                    getRandomNumber(0, 999999999)
                ).append("/release-keys,").append("universal").append(getRandomNumber(0, 99999))
                .append(",").append(brand).append(",").append(model).append(",").append(brand)
                .append("/").append(brand).append("/").append(model).append(":")
                .append(androidVersion).append("/").append(
                    getRandomNumber(0, 999999999)
                ).append(":").append("user/release-keys,").append(getRandomNumber(0, 999999999))
                .append(",").append(model)
            val length = chrplus(stringBuilder6.toString())
            stringBuilder6.append(",").append(length - 907).append(",")
                .append(getRandomNumber(1, 9999)).append(",").append(
                    System.currentTimeMillis() / 2
                ).append("-1,2,-94,-101,").append("do_unr,dm_en,t_en").append("-1,2,-94,-102,")
                .append("-1,2,-94,-108,").append(
                    randomEvent()
                ).append("-1,2,-94,-117,").append(touchEvent()).append("-1,2,-94,-144,")
                .append("-1,2,-94,-142,").append("-1,2,-94,-145,").append("-1,2,-94,-143,")
                .append("-1,2,-94,-115,").append(
                    randomPair()
                ).append("-1,2,-94,-70,").append("-1,2,-94,-80,").append("-1,2,-94,-120,")
                .append("-1,2,-94,-112,").append(
                    randomActivity2()
                ).append("-1,2,-94,-103,").append(activities())
            val sensor = encryptSensor(stringBuilder6.toString())
            return "$sensor|$SDKINT|$brand|$model|$androidVersion|"
        }

    fun encryptSensor(str: String): String? {
        var result: String? = null
        try {
            initEncryptKey()
            val uptimeMillis = getUptimeKotlin()
            val instance = Cipher.getInstance("AES/CBC/PKCS5Padding")
            instance.init(1, aesKey)
            val doFinal = instance.doFinal(str.toByteArray())
            val aesUptime = (getUptimeKotlin() - uptimeMillis) * 1000
            val iv = instance.iv
            val obj = ByteArray(doFinal.size + iv.size)
            System.arraycopy(iv, 0, obj, 0, iv.size)
            System.arraycopy(doFinal, 0, obj, iv.size, doFinal.size)
            val uptimeMillis2 = getUptimeKotlin()
            val secretKeySpec: Key = SecretKeySpec(hmacKey!!.encoded, "HmacSHA256")
            val instance2 = Mac.getInstance("HmacSHA256")
            instance2.init(secretKeySpec)
            val iv2 = instance2.doFinal(obj)
            val doFinal2 = ByteArray(obj.size + iv2.size)
            val hmackUptime = (getUptimeKotlin() - uptimeMillis2) * 1000
            System.arraycopy(obj, 0, doFinal2, 0, obj.size)
            System.arraycopy(iv2, 0, doFinal2, obj.size, iv2.size)
            val uptimeMillis3 = getUptimeKotlin()
            val encryptedData = Base64.getEncoder().encodeToString(doFinal2)
            val b64uptime = 1000 * (getUptimeKotlin() - uptimeMillis3)
            val sb = StringBuilder()
            sb.append("2,a,")
            sb.append(aesKeyEncrypted)
            sb.append(",")
            sb.append(hmacKeyEncrypted)
            sb.append("$")
            sb.append(encryptedData)
            sb.append("$")
            sb.append(aesUptime).append(",").append(hmackUptime).append(",").append(b64uptime)
            sb.append("$$")
            result = sb.toString()
        } catch (e: Exception) {
        }
        return result
    }

    private fun initEncryptKey() {
        if (aesKey != null) {
            return
        }
        try {
            val keyGen = KeyGenerator.getInstance("AES")
            aesKey = keyGen.generateKey()
            val hmacKeyGen = KeyGenerator.getInstance("HmacSHA256")
            hmacKey = hmacKeyGen.generateKey()
            val keySpec = X509EncodedKeySpec(
                Base64.getDecoder()
                    .decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4sA7vA7N/t1SRBS8tugM2X4bByl0jaCZLqxPOql+qZ3sP4UFayqJTvXjd7eTjMwg1T70PnmPWyh1hfQr4s12oSVphTKAjPiWmEBvcpnPPMjr5fGgv0w6+KM9DLTxcktThPZAGoVcoyM/cTO/YsAMIxlmTzpXBaxddHRwi8S2NvwIDAQAB")
            )
            val factory = KeyFactory.getInstance("RSA")
            val rsaKey = factory.generatePublic(keySpec)
            val rsaInstance = Cipher.getInstance("RSA/ECB/PKCS1PADDING")
            rsaInstance.init(1, rsaKey)
            aesKeyEncrypted = Base64.getEncoder().encodeToString(
                rsaInstance.doFinal(aesKey?.getEncoded())
            )
            hmacKeyEncrypted = Base64.getEncoder().encodeToString(
                rsaInstance.doFinal(hmacKey?.getEncoded())
            )
        } catch (e: Exception) {
        }
    }

    companion object {
        var uptime: Long = 0
        var startTime = System.currentTimeMillis()
        fun getUptimeKotlin(): Long {
            return uptime + (System.currentTimeMillis() - startTime)
        }

        fun randomActivity2(): String {
            return getRandomNumber(0, 200000).toString() + "," + getRandomNumber(
                0,
                200000
            ) + "," + getRandomNumber(0, 200000) + "," + getRandomNumber(
                0,
                200000
            ) + "," + getRandomNumber(0, 200000) + "," + getRandomNumber(
                0,
                200000
            ) + "," + getRandomNumber(0, 200000) + "," + getRandomNumber(
                0,
                200000
            ) + "," + getRandomNumber(0, 200000)
        }

        fun activities(): String {
            val sb = StringBuilder()
            val cycleNum = getRandomNumber(10, 50)
            for (i in 0 until cycleNum) {
                sb.append("2")
                sb.append(",")
                sb.append(System.currentTimeMillis() + getRandomNumber(0, 50000))
                sb.append(";")
                sb.append("3")
                sb.append(",")
                sb.append(System.currentTimeMillis() + getRandomNumber(50000, 1000000))
                sb.append(";")
            }
            return sb.toString()
        }

        fun randomPair(): String {
            val randomEvent = randomEvent()
            val str = touchEvent()
            val randomNumber = getRandomNumber(0, 10000)
            val randomNumber2 = getRandomNumber(0, 10000)
            val randomLong = getRandomLong(4294967295L, 999999999999999999L)
            val currentTimeMillis = System.currentTimeMillis()
            val randomNumber3 = getRandomNumber(0, 10000)
            val randomLong2 = getRandomLong(4294967295L, 999999999999999999L)
            val randomNumber4 = getRandomNumber(0, 1000000)
            val uptime2 = getUptimeKotlin()
            getRandomNumber(0, 10000)
            getRandomLong(4294967295L, 999999999999999999L)
            System.currentTimeMillis()
            getRandomNumber(0, 10000)
            return "$randomEvent,$str,$randomNumber,$randomNumber2,$randomLong,$randomEvent,0,0,$currentTimeMillis,$randomEvent,$randomNumber3,$randomLong2,$randomEvent,$randomNumber4,$uptime2,$randomEvent,0"
        }

        fun randomEvent(): String {
            val sb = StringBuilder()
            val maxScreenSize = maxScreenSize
            val cycleNum = getRandomNumber(10, 50)
            for (i in 0 until cycleNum) {
                sb.append("2")
                sb.append(",")
                sb.append(getRandomNumber(0, maxScreenSize))
                sb.append(",")
                sb.append(getRandomNumber(0, maxScreenSize))
                sb.append(";")
            }
            return sb.toString()
        }

        fun touchEvent(): String {
            val sb = StringBuilder()
            val maxScreenSize = maxScreenSize
            val cycleNum = getRandomNumber(10, 50)
            for (i in 0 until cycleNum) {
                sb.append(getRandomNumber(2, 3))
                sb.append(",")
                sb.append(getRandomNumber(0, maxScreenSize))
                sb.append(",0,0,1,1,1,-1;")
            }
            return sb.toString()
        }

        fun getRandomNumber(min: Int, max: Int): Int {
            return (Math.random() * (max - min) + min).toInt()
        }

        fun getRandomLong(min: Long, max: Long): Long {
            return (Math.random() * (max - min) + min).toLong()
        }

        val maxScreenSize: Int
            get() {
                val screenInt = DeviceInfo.randomScreenSize().split(",".toRegex())
                    .dropLastWhile { it.isEmpty() }
                    .toTypedArray()
                val b1 = screenInt[0].toInt()
                val b2 = screenInt[1].toInt()
                return Math.max(b1, b2)
            }

        fun chrplus(paramString: String?): Int {
            if (paramString != null && !paramString.trim { it <= ' ' }
                    .equals("", ignoreCase = true)) {
                var c = 0.toChar()
                for (b in 0 until paramString.length) {
                    try {
                        val c2 = paramString[b]
                        if (c2.code < 128) {
                            c = (c.code + c2.code).toChar()
                        }
                    } catch (e: Exception) {
                        return -2
                    }
                }
                return c.code
            }
            return -1
        }

        @JvmStatic
        fun main(args: Array<String>) {
            println(SensorDataKotlin().sensorData)
        }
    }

}