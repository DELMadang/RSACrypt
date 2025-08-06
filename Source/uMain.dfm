object frmMain: TfrmMain
  Left = 0
  Top = 0
  Caption = 'RSA '#50516#48373#54840#54868
  ClientHeight = 577
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = HANGEUL_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = #47569#51008' '#44256#46357
  Font.Style = []
  TextHeight = 15
  object eLog: TMemo
    Left = 8
    Top = 19
    Width = 608
    Height = 519
    Lines.Strings = (
      'eLog')
    ScrollBars = ssVertical
    TabOrder = 0
  end
  object btnTest: TButton
    Left = 541
    Top = 544
    Width = 75
    Height = 25
    Caption = #53580#49828#53944
    TabOrder = 1
    OnClick = btnTestClick
  end
end
