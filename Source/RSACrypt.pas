unit RSACrypt;

interface

uses
  System.SysUtils,
  System.Classes,
  Winapi.Windows;

const
  PROV_RSA_FULL = 1;
  CRYPT_VERIFYCONTEXT = $F0000000;
  CRYPT_EXPORTABLE = $00000001;
  AT_KEYEXCHANGE = 1;
  AT_SIGNATURE = 2;
  PUBLICKEYBLOB = $6;
  PRIVATEKEYBLOB = $7;
  SIMPLEBLOB = $1;
  CRYPT_STRING_BASE64 = $00000001;

type
  HCRYPTPROV = ULONG_PTR;
  HCRYPTKEY = ULONG_PTR;
  PHCRYPTPROV = ^HCRYPTPROV;
  PHCRYPTKEY = ^HCRYPTKEY;
  ALG_ID = ULONG;

type
  TRSACrypto = class
  private
    FhProv: HCRYPTPROV;
    FhKey: HCRYPTKEY;
    FKeySize: DWORD;
    procedure CheckError(ASuccess: Boolean; const AMessage: string);
  public
    constructor Create(AKeySize: DWORD = 2048);
    destructor Destroy; override;

    // 키 관리
    function  ExportPrivateKey: TBytes;
    function  ExportPublicKey: TBytes;
    procedure GenerateKeyPair;
    procedure ImportPrivateKey(const APrivateKey: TBytes);
    procedure ImportPublicKey(const APublicKey: TBytes);

    // 암호화/복호화
    function  Encrypt(const AData: TBytes): TBytes;
    function  Decrypt(const AEncryptedData: TBytes): TBytes;

    // 문자열 헬퍼 메서드
    function  EncryptString(const AText: string): TBytes;
    function  DecryptToString(const AEncryptedData: TBytes): string;

    // Base64 유틸리티
    class function BytesToBase64(const ABytes: TBytes): string;
    class function Base64ToBytes(const ABase64: string): TBytes;
  end;

  // RSA 예외 클래스
  ERSACryptoException = class(Exception);

implementation

// CryptoAPI 함수 선언
function CryptAcquireContext(phProv: PHCRYPTPROV; pszContainer: PChar;
  pszProvider: PChar; dwProvType: DWORD; dwFlags: DWORD): BOOL; stdcall;
  external 'advapi32.dll' name 'CryptAcquireContextW';

function CryptReleaseContext(hProv: HCRYPTPROV; dwFlags: DWORD): BOOL; stdcall;
  external 'advapi32.dll';

function CryptGenKey(hProv: HCRYPTPROV; Algid: ALG_ID; dwFlags: DWORD;
  phKey: PHCRYPTKEY): BOOL; stdcall;
  external 'advapi32.dll';

function CryptDestroyKey(hKey: HCRYPTKEY): BOOL; stdcall;
  external 'advapi32.dll';

function CryptExportKey(hKey: HCRYPTKEY; hExpKey: HCRYPTKEY;
  dwBlobType: DWORD; dwFlags: DWORD; pbData: PBYTE;
  pdwDataLen: PDWORD): BOOL; stdcall;
  external 'advapi32.dll';

function CryptImportKey(hProv: HCRYPTPROV; pbData: PBYTE;
  dwDataLen: DWORD; hPubKey: HCRYPTKEY; dwFlags: DWORD;
  phKey: PHCRYPTKEY): BOOL; stdcall;
  external 'advapi32.dll';

function CryptEncrypt(hKey: HCRYPTKEY; hHash: ULONG_PTR;
  Final: BOOL; dwFlags: DWORD; pbData: PBYTE; pdwDataLen: PDWORD;
  dwBufLen: DWORD): BOOL; stdcall;
  external 'advapi32.dll';

function CryptDecrypt(hKey: HCRYPTKEY; hHash: ULONG_PTR;
  Final: BOOL; dwFlags: DWORD; pbData: PBYTE;
  pdwDataLen: PDWORD): BOOL; stdcall;
  external 'advapi32.dll';

function CryptBinaryToString(pbBinary: PBYTE; cbBinary: DWORD;
  dwFlags: DWORD; pszString: PChar; pcchString: PDWORD): BOOL; stdcall;
  external 'crypt32.dll' name 'CryptBinaryToStringW';

function CryptStringToBinary(pszString: PChar; cchString: DWORD;
  dwFlags: DWORD; pbBinary: PBYTE; pcbBinary: PDWORD;
  pdwSkip: PDWORD; pdwFlags: PDWORD): BOOL; stdcall;
  external 'crypt32.dll' name 'CryptStringToBinaryW';

{ TRSACrypto }

constructor TRSACrypto.Create(AKeySize: DWORD);
begin
  inherited Create;
  FKeySize := AKeySize;
  FhProv := 0;
  FhKey := 0;

  // CryptoAPI 컨텍스트 획득
  CheckError(
    CryptAcquireContext(
      @FhProv,
      nil,
      nil,
      PROV_RSA_FULL,
      CRYPT_VERIFYCONTEXT
    ),
    'CryptoAPI 컨텍스트를 획득할 수 없습니다'
  );
end;

destructor TRSACrypto.Destroy;
begin
  if FhKey <> 0 then
    CryptDestroyKey(FhKey);

  if FhProv <> 0 then
    CryptReleaseContext(FhProv, 0);

  inherited;
end;

procedure TRSACrypto.CheckError(ASuccess: Boolean; const AMessage: string);
var
  ErrorCode: DWORD;
begin
  if not ASuccess then
  begin
    ErrorCode := GetLastError;
    raise ERSACryptoException.CreateFmt('%s (에러 코드: %d)', [AMessage, ErrorCode]);
  end;
end;

procedure TRSACrypto.GenerateKeyPair;
var
  Flags: DWORD;
begin
  // 기존 키가 있으면 삭제
  if FhKey <> 0 then
  begin
    CryptDestroyKey(FhKey);
    FhKey := 0;
  end;

  // RSA 키 쌍 생성
  // 상위 16비트에 키 크기 지정
  Flags := (FKeySize shl 16) or CRYPT_EXPORTABLE;

  CheckError(
    CryptGenKey(
      FhProv,
      AT_KEYEXCHANGE,  // RSA 키 교환용
      Flags,
      @FhKey
    ),
    'RSA 키 쌍을 생성할 수 없습니다'
  );
end;

function TRSACrypto.ExportPublicKey: TBytes;
var
  DataLen: DWORD;
begin
  DataLen := 0;

  // 필요한 버퍼 크기 확인
  CheckError(
    CryptExportKey(
      FhKey,
      0,
      PUBLICKEYBLOB,
      0,
      nil,
      @DataLen
    ),
    '공개키 크기를 확인할 수 없습니다'
  );

  SetLength(Result, DataLen);

  // 공개키 내보내기
  CheckError(
    CryptExportKey(
      FhKey,
      0,
      PUBLICKEYBLOB,
      0,
      @Result[0],
      @DataLen
    ),
    '공개키를 내보낼 수 없습니다'
  );
end;

function TRSACrypto.ExportPrivateKey: TBytes;
var
  DataLen: DWORD;
begin
  DataLen := 0;

  // 필요한 버퍼 크기 확인
  CheckError(
    CryptExportKey(
      FhKey,
      0,
      PRIVATEKEYBLOB,
      0,
      nil,
      @DataLen
    ),
    '개인키 크기를 확인할 수 없습니다'
  );

  SetLength(Result, DataLen);

  // 개인키 내보내기
  CheckError(
    CryptExportKey(
      FhKey,
      0,
      PRIVATEKEYBLOB,
      0,
      @Result[0],
      @DataLen
    ),
    '개인키를 내보낼 수 없습니다'
  );
end;

procedure TRSACrypto.ImportPublicKey(const APublicKey: TBytes);
begin
  // 기존 키가 있으면 삭제
  if FhKey <> 0 then
  begin
    CryptDestroyKey(FhKey);
    FhKey := 0;
  end;

  // 공개키 가져오기
  CheckError(
    CryptImportKey(
      FhProv,
      @APublicKey[0],
      Length(APublicKey),
      0,
      0,
      @FhKey
    ),
    '공개키를 가져올 수 없습니다'
  );
end;

procedure TRSACrypto.ImportPrivateKey(const APrivateKey: TBytes);
begin
  // 기존 키가 있으면 삭제
  if FhKey <> 0 then
  begin
    CryptDestroyKey(FhKey);
    FhKey := 0;
  end;

  // 개인키 가져오기
  CheckError(
    CryptImportKey(
      FhProv,
      @APrivateKey[0],
      Length(APrivateKey),
      0,
      0,
      @FhKey
    ),
    '개인키를 가져올 수 없습니다'
  );
end;

function TRSACrypto.Encrypt(const AData: TBytes): TBytes;
var
  DataLen: DWORD;
  BufferLen: DWORD;
  TempData: TBytes;
begin
  if FhKey = 0 then
    raise ERSACryptoException.Create('암호화를 위한 키가 설정되지 않았습니다');

  // CryptEncrypt는 데이터를 역순으로 처리하므로 복사본 생성
  TempData := Copy(AData, 0, Length(AData));
  DataLen := Length(TempData);
  BufferLen := DataLen;

  // 필요한 버퍼 크기 확인
  CheckError(
    CryptEncrypt(
      FhKey,
      0,
      True,
      0,
      nil,
      @BufferLen,
      0
    ),
    '암호화 버퍼 크기를 확인할 수 없습니다'
  );

  SetLength(TempData, BufferLen);
  DataLen := Length(AData);
  Move(AData[0], TempData[0], DataLen);

  // 실제 암호화
  CheckError(
    CryptEncrypt(
      FhKey,
      0,
      True,
      0,
      @TempData[0],
      @DataLen,
      BufferLen
    ),
    '데이터를 암호화할 수 없습니다'
  );

  SetLength(Result, DataLen);
  Move(TempData[0], Result[0], DataLen);
end;

function TRSACrypto.Decrypt(const AEncryptedData: TBytes): TBytes;
var
  DataLen: DWORD;
  TempData: TBytes;
begin
  if FhKey = 0 then
    raise ERSACryptoException.Create('복호화를 위한 키가 설정되지 않았습니다');

  // 복호화를 위한 데이터 복사
  TempData := Copy(AEncryptedData, 0, Length(AEncryptedData));
  DataLen := Length(TempData);

  // 실제 복호화
  CheckError(
    CryptDecrypt(
      FhKey,
      0,
      True,
      0,
      @TempData[0],
      @DataLen
    ),
    '데이터를 복호화할 수 없습니다'
  );

  SetLength(Result, DataLen);
  Move(TempData[0], Result[0], DataLen);
end;

function TRSACrypto.EncryptString(const AText: string): TBytes;
var
  UTF8Bytes: TBytes;
begin
  UTF8Bytes := TEncoding.UTF8.GetBytes(AText);
  Result := Encrypt(UTF8Bytes);
end;

function TRSACrypto.DecryptToString(const AEncryptedData: TBytes): string;
var
  DecryptedBytes: TBytes;
begin
  DecryptedBytes := Decrypt(AEncryptedData);
  Result := TEncoding.UTF8.GetString(DecryptedBytes);
end;

class function TRSACrypto.BytesToBase64(const ABytes: TBytes): string;
var
  Base64Len: DWORD;
begin
  Base64Len := 0;

  // 필요한 버퍼 크기 계산
  if CryptBinaryToString(@ABytes[0], Length(ABytes), CRYPT_STRING_BASE64,
                          nil, @Base64Len) then
  begin
    SetLength(Result, Base64Len);
    CryptBinaryToString(@ABytes[0], Length(ABytes), CRYPT_STRING_BASE64,
                        PChar(Result), @Base64Len);
    // 개행 문자 제거
    Result := StringReplace(Result, #13#10, '', [rfReplaceAll]);
    Result := Trim(Result);
  end
  else
    Result := '';
end;

class function TRSACrypto.Base64ToBytes(const ABase64: string): TBytes;
var
  BinaryLen: DWORD;
begin
  BinaryLen := 0;

  // 필요한 버퍼 크기 계산
  if CryptStringToBinary(PChar(ABase64), Length(ABase64), CRYPT_STRING_BASE64,
                         nil, @BinaryLen, nil, nil) then
  begin
    SetLength(Result, BinaryLen);
    CryptStringToBinary(PChar(ABase64), Length(ABase64), CRYPT_STRING_BASE64,
                        @Result[0], @BinaryLen, nil, nil);
  end
  else
    SetLength(Result, 0);
end;

end.
