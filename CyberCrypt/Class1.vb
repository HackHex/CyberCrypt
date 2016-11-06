Imports System.Security.Cryptography
Imports System.IO
Imports System.Text

Public Class _AES256

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(31) As Byte
        For i As Integer = 0 To 31
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Private Shared Function CreateIV(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytIV(15) As Byte
        For i As Integer = 32 To 47
            bytIV(i - 32) = bytResult(i)
        Next
        Return bytIV 'Return the IV.
    End Function

    Private Shared Function AES_Encrypt(bytesToBeEncrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim encryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Using ms As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 256
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC
                Using cs = New CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length)
                    cs.Close()
                End Using
                encryptedBytes = ms.ToArray()
            End Using
        End Using
        Return encryptedBytes
    End Function

    Private Shared Function AES_Decrypt(bytesToBeDecrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim decryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Using ms As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 256
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC
                Using cs = New CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length)
                    cs.Close()
                End Using
                decryptedBytes = ms.ToArray()
            End Using
        End Using
        Return decryptedBytes
    End Function

    Public Shared Sub EncryptFile(File_Path As String, password As String)
        Dim bytesToBeEncrypted As Byte() = File.ReadAllBytes(File_Path)
        Dim passwordBytes As Byte() = CreateKey(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesEncrypted As Byte() = AES_Encrypt(bytesToBeEncrypted, passwordBytes)
        File.WriteAllBytes(File_Path, bytesEncrypted)
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, password As String)
        Dim bytesToBeDecrypted As Byte() = File.ReadAllBytes(File_Path)
        Dim passwordBytes As Byte() = CreateKey(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesDecrypted As Byte() = AES_Decrypt(bytesToBeDecrypted, passwordBytes)
        File.WriteAllBytes(File_Path, bytesDecrypted)
    End Sub

End Class

Public Class _AES192

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(24) As Byte
        For i As Integer = 0 To 24
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Private Shared Function CreateIV(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytIV(15) As Byte
        For i As Integer = 25 To 40
            bytIV(i - 25) = bytResult(i)
        Next
        Return bytIV 'Return the IV.
    End Function

    Private Shared Function AES_Encrypt(bytesToBeEncrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim encryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Using ms As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 192
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC
                Using cs = New CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length)
                    cs.Close()
                End Using
                encryptedBytes = ms.ToArray()
            End Using
        End Using
        Return encryptedBytes
    End Function

    Private Shared Function AES_Decrypt(bytesToBeDecrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim decryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Using ms As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 192
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC
                Using cs = New CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length)
                    cs.Close()
                End Using
                decryptedBytes = ms.ToArray()
            End Using
        End Using
        Return decryptedBytes
    End Function

    Public Shared Sub EncryptFile(File_Path As String, password As String)
        Dim bytesToBeEncrypted As Byte() = File.ReadAllBytes(File_Path)
        Dim passwordBytes As Byte() = CreateKey(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesEncrypted As Byte() = AES_Encrypt(bytesToBeEncrypted, passwordBytes)
        File.WriteAllBytes(File_Path, bytesEncrypted)
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, password As String)
        Dim bytesToBeDecrypted As Byte() = File.ReadAllBytes(File_Path)
        Dim passwordBytes As Byte() = CreateKey(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesDecrypted As Byte() = AES_Decrypt(bytesToBeDecrypted, passwordBytes)
        File.WriteAllBytes(File_Path, bytesDecrypted)
    End Sub

End Class

Public Class _AES128

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(15) As Byte
        For i As Integer = 0 To 15
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Private Shared Function CreateIV(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytIV(15) As Byte
        For i As Integer = 16 To 31
            bytIV(i - 16) = bytResult(i)
        Next
        Return bytIV 'Return the IV.
    End Function

    Private Shared Function AES_Encrypt(bytesToBeEncrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim encryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Using ms As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 128
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC
                Using cs = New CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length)
                    cs.Close()
                End Using
                encryptedBytes = ms.ToArray()
            End Using
        End Using
        Return encryptedBytes
    End Function

    Private Shared Function AES_Decrypt(bytesToBeDecrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim decryptedBytes As Byte() = Nothing
        Dim saltBytes As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Using ms As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 128
                AES.BlockSize = 128
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)
                AES.Mode = CipherMode.CBC
                Using cs = New CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length)
                    cs.Close()
                End Using
                decryptedBytes = ms.ToArray()
            End Using
        End Using
        Return decryptedBytes
    End Function

    Public Shared Sub EncryptFile(File_Path As String, password As String)
        Dim bytesToBeEncrypted As Byte() = File.ReadAllBytes(File_Path)
        Dim passwordBytes As Byte() = CreateKey(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesEncrypted As Byte() = AES_Encrypt(bytesToBeEncrypted, passwordBytes)
        File.WriteAllBytes(File_Path, bytesEncrypted)
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, password As String)
        Dim bytesToBeDecrypted As Byte() = File.ReadAllBytes(File_Path)
        Dim passwordBytes As Byte() = CreateKey(password)
        passwordBytes = SHA256.Create().ComputeHash(passwordBytes)
        Dim bytesDecrypted As Byte() = AES_Decrypt(bytesToBeDecrypted, passwordBytes)
        File.WriteAllBytes(File_Path, bytesDecrypted)
    End Sub

End Class

Public Class _3DES256

    Private Shared Key() As Byte
    Private Shared FilePath As String
    Private Shared data As Byte()

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(31) As Byte
        For i As Integer = 0 To 31
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Private Shared Function CreateIV(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytIV(7) As Byte
        For i As Integer = 32 To 39
            bytIV(i - 32) = bytResult(i)
        Next
        Return bytIV 'Return the IV.
    End Function

    Public Shared Sub EncryptFile(File_Path As String, KEY As String)
        _3DES256.Key = CreateKey(KEY)
        _3DES256.FilePath = File_Path
        data = File.ReadAllBytes(FilePath)
        Encrypt()
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, KEY As String)
        _3DES256.Key = CreateKey(KEY)
        _3DES256.FilePath = File_Path
        data = File.ReadAllBytes(FilePath)
        Decrypt()
    End Sub

    Private Shared Sub Encrypt()
        Dim key__1 As Byte() = Key
        Dim iv__2 As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Dim enc As Byte() = New Byte(-1) {}
        Dim tdes As TripleDES = TripleDES.Create()
        tdes.KeySize = 256
        tdes.IV = iv__2
        tdes.Key = key__1
        tdes.Mode = CipherMode.CBC
        tdes.Padding = PaddingMode.Zeros
        Dim ict As ICryptoTransform = tdes.CreateEncryptor()
        enc = ict.TransformFinalBlock(data, 0, data.Length)
        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In enc
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

    Private Shared Sub Decrypt()
        Dim key__1 As Byte() = Key
        Dim iv__2 As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Dim dec As Byte() = New Byte(-1) {}
        Dim tdes As TripleDES = TripleDES.Create()
        tdes.KeySize = 256
        tdes.IV = iv__2
        tdes.Key = key__1
        tdes.Mode = CipherMode.CBC
        tdes.Padding = PaddingMode.Zeros
        Dim ict As ICryptoTransform = tdes.CreateDecryptor()
        dec = ict.TransformFinalBlock(data, 0, data.Length)
        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In dec
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

End Class

Public Class _3DES192

    Private Shared Key() As Byte
    Private Shared FilePath As String
    Private Shared data As Byte()

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(23) As Byte
        For i As Integer = 0 To 23
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Private Shared Function CreateIV(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytIV(7) As Byte
        For i As Integer = 24 To 31
            bytIV(i - 24) = bytResult(i)
        Next
        Return bytIV 'Return the IV.
    End Function

    Public Shared Sub EncryptFile(File_Path As String, KEY As String)
        _3DES192.Key = CreateKey(KEY)
        _3DES192.FilePath = File_Path
        data = File.ReadAllBytes(FilePath)
        Encrypt()
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, KEY As String)
        _3DES192.Key = CreateKey(KEY)
        _3DES192.FilePath = File_Path
        data = File.ReadAllBytes(FilePath)
        Decrypt()
    End Sub

    Private Shared Sub Encrypt()
        Dim key__1 As Byte() = Key
        Dim iv__2 As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Dim enc As Byte() = New Byte(-1) {}
        Dim tdes As TripleDES = TripleDES.Create()
        tdes.KeySize = 192
        tdes.IV = iv__2
        tdes.Key = key__1
        tdes.Mode = CipherMode.CBC
        tdes.Padding = PaddingMode.Zeros
        Dim ict As ICryptoTransform = tdes.CreateEncryptor()
        enc = ict.TransformFinalBlock(data, 0, data.Length)
        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In enc
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

    Private Shared Sub Decrypt()
        Dim key__1 As Byte() = Key
        Dim iv__2 As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Dim dec As Byte() = New Byte(-1) {}
        Dim tdes As TripleDES = TripleDES.Create()
        tdes.KeySize = 192
        tdes.IV = iv__2
        tdes.Key = key__1
        tdes.Mode = CipherMode.CBC
        tdes.Padding = PaddingMode.Zeros
        Dim ict As ICryptoTransform = tdes.CreateDecryptor()
        dec = ict.TransformFinalBlock(data, 0, data.Length)
        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In dec
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

End Class

Public Class _3DES128
    Private Shared Key() As Byte
    Private Shared FilePath As String
    Private Shared data As Byte()

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(15) As Byte
        For i As Integer = 0 To 15
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Private Shared Function CreateIV(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytIV(7) As Byte
        For i As Integer = 16 To 23
            bytIV(i - 16) = bytResult(i)
        Next
        Return bytIV 'Return the IV.
    End Function

    Public Shared Sub EncryptFile(File_Path As String, KEY As String)
        _3DES128.Key = CreateKey(KEY)
        _3DES128.FilePath = File_Path
        data = File.ReadAllBytes(FilePath)
        Encrypt()
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, KEY As String)
        _3DES128.Key = CreateKey(KEY)
        _3DES128.FilePath = File_Path
        data = File.ReadAllBytes(FilePath)
        Decrypt()
    End Sub

    Private Shared Sub Encrypt()
        Dim key__1 As Byte() = Key
        Dim iv__2 As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Dim enc As Byte() = New Byte(-1) {}
        Dim tdes As TripleDES = TripleDES.Create()
        tdes.KeySize = 128
        tdes.IV = iv__2
        tdes.Key = key__1
        tdes.Mode = CipherMode.CBC
        tdes.Padding = PaddingMode.Zeros
        Dim ict As ICryptoTransform = tdes.CreateEncryptor()
        enc = ict.TransformFinalBlock(data, 0, data.Length)
        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In enc
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

    Private Shared Sub Decrypt()
        Dim key__1 As Byte() = Key
        Dim iv__2 As Byte() = CreateIV("ReflectDataSecretIV!@#$%^&*()")
        Dim dec As Byte() = New Byte(-1) {}
        Dim tdes As TripleDES = TripleDES.Create()
        tdes.KeySize = 128
        tdes.IV = iv__2
        tdes.Key = key__1
        tdes.Mode = CipherMode.CBC
        tdes.Padding = PaddingMode.Zeros
        Dim ict As ICryptoTransform = tdes.CreateDecryptor()
        dec = ict.TransformFinalBlock(data, 0, data.Length)
        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In dec
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

End Class

Public Class _RC4
    Private Shared Key() As Byte
    Private Shared FilePath As String
    Private Shared data As Byte()

    Private Shared Function CreateKey(ByVal strPassword As String) As Byte()
        Dim chrData() As Char = strPassword.ToCharArray
        Dim intLength As Integer = chrData.GetUpperBound(0)
        Dim bytDataToHash(intLength) As Byte
        For i As Integer = 0 To chrData.GetUpperBound(0)
            bytDataToHash(i) = CByte(Asc(chrData(i)))
        Next
        Dim SHA512 As New System.Security.Cryptography.SHA512Managed
        Dim bytResult As Byte() = SHA512.ComputeHash(bytDataToHash)
        Dim bytKey(15) As Byte
        For i As Integer = 0 To 15
            bytKey(i) = bytResult(i)
        Next
        Return bytKey 'Return the key.
    End Function

    Public Shared Sub EncryptFile(File_Path As String, KEY As String)
        _RC4.Key = CreateKey(KEY)
        _RC4.FilePath = File_Path
        _RC4.data = File.ReadAllBytes(FilePath)
        Encrypt()
    End Sub

    Public Shared Sub DecryptFile(File_Path As String, KEY As String)
        _RC4.Key = CreateKey(KEY)
        _RC4.FilePath = File_Path
        _RC4.data = File.ReadAllBytes(FilePath)
        Decrypt()
    End Sub

    Private Shared Sub Encrypt()
        Dim a As Integer, i As Integer, j As Integer, k As Integer, tmp As Integer
        Dim key As Integer(), box As Integer()
        Dim cipher As Byte()

        key = New Integer(127) {}
        box = New Integer(127) {}
        cipher = New Byte(data.Length - 1) {}

        For i = 0 To 127
            key(i) = key(i Mod key.Length)
            box(i) = i
        Next
        j = InlineAssignHelper(i, 0)
        While i < 128
            j = (j + box(i) + key(i)) Mod 128
            tmp = box(i)
            box(i) = box(j)
            box(j) = tmp
            i += 1
        End While
        a = InlineAssignHelper(j, InlineAssignHelper(i, 0))
        While i < data.Length
            a += 1
            a = a Mod 128
            j += box(a)
            j = j Mod 128
            tmp = box(a)
            box(a) = box(j)
            box(j) = tmp
            k = box(((box(a) + box(j)) Mod 128))
            cipher(i) = CByte(data(i) Xor k)
            i += 1
        End While

        Dim Output As New FileStream(FilePath, FileMode.Create)
        For Each each_byte As Byte In cipher
            Output.WriteByte(each_byte)
        Next
        Output.Close()
    End Sub

    Private Shared Sub Decrypt()
        Encrypt()
    End Sub

    Private Shared Function InlineAssignHelper(Of T)(ByRef target As T, ByVal value As T) As T
        target = value
        Return value
    End Function

End Class

Public Class _MD5

    Public Shared Function GetMD5Hash(theInput As String) As String
        Using hasher As MD5 = MD5.Create()
            Dim dbytes As Byte() =
             hasher.ComputeHash(Encoding.UTF8.GetBytes(theInput))
            Dim sBuilder As New StringBuilder()
            For n As Integer = 0 To dbytes.Length - 1
                sBuilder.Append(dbytes(n).ToString("X2"))
            Next n
            Return sBuilder.ToString()
        End Using
    End Function

End Class

Public Class _SHA

    Public Shared Function SHA1Hash(ByVal theInput As String) As String
        Dim sha1Obj As New Security.Cryptography.SHA1CryptoServiceProvider
        Dim bytesToHash() As Byte = System.Text.Encoding.ASCII.GetBytes(theInput)
        bytesToHash = sha1Obj.ComputeHash(bytesToHash)
        Dim strResult As String = ""
        For Each b As Byte In bytesToHash
            strResult += b.ToString("x2")
        Next
        Return strResult
    End Function

    Public Shared Function SHA256Hash(ByVal theInput As String) As String
        Dim sha1Obj As New Security.Cryptography.SHA256Managed
        Dim bytesToHash() As Byte = System.Text.Encoding.ASCII.GetBytes(theInput)
        bytesToHash = sha1Obj.ComputeHash(bytesToHash)
        Dim strResult As String = ""
        For Each b As Byte In bytesToHash
            strResult += b.ToString("x2")
        Next
        Return strResult
    End Function

    Public Shared Function SHA384Hash(ByVal theInput As String) As String
        Dim sha1Obj As New Security.Cryptography.SHA384Managed
        Dim bytesToHash() As Byte = System.Text.Encoding.ASCII.GetBytes(theInput)
        bytesToHash = sha1Obj.ComputeHash(bytesToHash)
        Dim strResult As String = ""
        For Each b As Byte In bytesToHash
            strResult += b.ToString("x2")
        Next
        Return strResult
    End Function

    Public Shared Function SHA512Hash(ByVal theInput As String) As String
        Dim sha1Obj As New Security.Cryptography.SHA512Managed
        Dim bytesToHash() As Byte = System.Text.Encoding.ASCII.GetBytes(theInput)
        bytesToHash = sha1Obj.ComputeHash(bytesToHash)
        Dim strResult As String = ""
        For Each b As Byte In bytesToHash
            strResult += b.ToString("x2")
        Next
        Return strResult
    End Function

End Class

Public Class _RIPEMD

    Public Shared Function RIPEMDHash(ByVal theInput As String) As String
        Dim sha1Obj As New Security.Cryptography.RIPEMD160Managed
        Dim bytesToHash() As Byte = System.Text.Encoding.ASCII.GetBytes(theInput)
        bytesToHash = sha1Obj.ComputeHash(bytesToHash)
        Dim strResult As String = ""
        For Each b As Byte In bytesToHash
            strResult += b.ToString("x2")
        Next
        Return strResult
    End Function

End Class