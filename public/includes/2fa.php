<?php
class LightweightTOTP {
    private const SECRET_LENGTH = 16;
    private const TIME_STEP = 30;

    public static function generateSecret() {
        $bytes = random_bytes(self::SECRET_LENGTH);
        return self::base32Encode($bytes);
    }

    public static function verifyCode($secret, $code, $discrepancy = 1) {
        $code = str_pad($code, 6, '0', STR_PAD_LEFT);
        $currentTimeSlice = floor(time() / self::TIME_STEP);

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = self::getCode($secret, $currentTimeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }
        return false;
    }

    public static function getQRCodeUrl($issuer, $accountName, $secret) {
        $encodedIssuer = rawurlencode($issuer);
        $encodedAccount = rawurlencode($accountName);
        return "otpauth://totp/{$encodedIssuer}:{$encodedAccount}?secret={$secret}&issuer={$encodedIssuer}&algorithm=SHA1&digits=6&period=30";
    }

    private static function getCode($secret, $timeSlice) {
        $secretKey = self::base32Decode($secret);
        $timePacked = pack('N*', 0) . pack('N*', $timeSlice);
        $hash = hash_hmac('SHA1', $timePacked, $secretKey, true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $hashPart = substr($hash, $offset, 4);
        $value = unpack('N', $hashPart)[1];
        $value = $value & 0x7FFFFFFF;
        $modulo = pow(10, 6);
        return str_pad($value % $modulo, 6, '0', STR_PAD_LEFT);
    }

    private static function base32Encode($data) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = '';
        $v = 0; $vBits = 0;
        for ($i = 0; $i < strlen($data); $i++) {
            $v = ($v << 8) | ord($data[$i]);
            $vBits += 8;
            while ($vBits >= 5) {
                $vBits -= 5;
                $result .= $chars[($v >> $vBits) & 31];
            }
        }
        if ($vBits > 0) {
            $result .= $chars[($v << (5 - $vBits)) & 31];
        }
        return $result;
    }

    private static function base32Decode($base32String) {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $data = '';
        $v = 0; $vBits = 0;
        $base32String = strtoupper(rtrim($base32String, '='));
        for ($i = 0; $i < strlen($base32String); $i++) {
            $index = strpos($chars, $base32String[$i]);
            if ($index === false) continue;
            $v = ($v << 5) | $index;
            $vBits += 5;
            if ($vBits >= 8) {
                $vBits -= 8;
                $data .= chr(($v >> $vBits) & 0xFF);
            }
        }
        return $data;
    }
}
?>