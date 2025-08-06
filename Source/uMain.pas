unit uMain;

interface

uses
  System.SysUtils,
  System.Classes,

  Vcl.Graphics,
  Vcl.Controls,
  Vcl.Forms,
  Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.Menus;

type
  TfrmMain = class(TForm)
    eLog: TMemo;
    btnTest: TButton;
    procedure btnTestClick(Sender: TObject);
  private
    procedure LogMessage(const AMessage: string);
    procedure ShowBytes(const AData: TBytes; AMaxBytes: Integer = 32);
    procedure TestBasicRSA;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

{$R *.dfm}

uses
  System.Math,
  RSACrypt;

procedure TfrmMain.btnTestClick(Sender: TObject);
begin
  eLog.Lines.Clear;
  TestBasicRSA;
end;

procedure TfrmMain.LogMessage(const AMessage: string);
begin
  eLog.Lines.Add(AMessage);
end;

procedure TfrmMain.ShowBytes(const AData: TBytes; AMaxBytes: Integer = 32);
var
  I: Integer;
begin
  for I := 0 to Min(AMaxBytes - 1, Length(AData) - 1) do
    LogMessage(Format('%.2X ', [AData[I]]));

  if Length(AData) > AMaxBytes then
    LogMessage('...');
end;

procedure TfrmMain.TestBasicRSA;
var
  RSA: TRSACrypto;
  PublicKey: TBytes;
  PrivateKey: TBytes;
  OriginalText: string;
  EncryptedData: TBytes;
  DecryptedText: string;
  PublicKeyB64: string;
begin
  LogMessage('========================================');
  LogMessage('RSA 암호화/복호화 테스트');
  LogMessage('========================================');

  RSA := TRSACrypto.Create(2048);
  try
    // 키 쌍 생성
    LogMessage('1. RSA 2048비트 키 쌍 생성... ');
    RSA.GenerateKeyPair;
    LogMessage('완료');

    // 키 내보내기
    PublicKey := RSA.ExportPublicKey;
    PrivateKey := RSA.ExportPrivateKey;
    LogMessage('2. 공개키 크기: ' + Length(PublicKey).ToString + ' bytes');
    LogMessage('   개인키 크기: ' + Length(PrivateKey).ToString + ' bytes');

    // Base64 변환 테스트
    PublicKeyB64 := TRSACrypto.BytesToBase64(PublicKey);
    LogMessage('   공개키 Base64 (일부): ' + Copy(PublicKeyB64, 1, 50) + '...');
    LogMessage('');

    // 암호화 테스트
    OriginalText := 'Hello RSA! 안녕하세요!';
    LogMessage('3. 원본: "' + OriginalText + '"');

    EncryptedData := RSA.EncryptString(OriginalText);
    LogMessage('4. 암호화 (' + Length(EncryptedData).ToString + ' bytes): ');
    ShowBytes(EncryptedData, 16);

    // 복호화 테스트
    DecryptedText := RSA.DecryptToString(EncryptedData);
    LogMessage('5. 복호화: "' + DecryptedText + '"');

    if OriginalText = DecryptedText then
      LogMessage('6. 결과: 성공!')
    else
      LogMessage('6. 결과: 실패!');
  finally
    RSA.Free;
  end;
end;

end.
