// Nanocurrency unit, Copyleft 2019 FL4RE - Daniel Mazur
unit Nano;

interface

uses
  AESObj, SPECKObj, FMX.Objects, IdHash, IdHashSHA, IdSSLOpenSSL, languages,
  System.Hash, MiscOBJ, SysUtils, System.IOUtils, HashObj, System.Types, System.UITypes,
  System.DateUtils, System.Generics.Collections, System.Classes, System.Variants,
  Math, FMX.Types, FMX.Graphics, FMX.Controls, FMX.Forms, FMX.Dialogs, FMX.StdCtrls,
  FMX.Controls.Presentation, FMX.Styles, System.ImageList, FMX.ImgList, FMX.Ani,
  FMX.Layouts, FMX.ExtCtrls, Velthuis.BigIntegers, FMX.ScrollBox, FMX.Memo, FMX.platform,
  FMX.TabControl, {$IF NOT DEFINED(LINUX)}System.Sensors, System.Sensors.Components, {$ENDIF}
  FMX.Edit, JSON, JSON.Builders, JSON.Readers, DelphiZXingQRCode, System.Net.HttpClientComponent,
  System.Net.HttpClient, keccak_n, tokenData, bech32, cryptoCurrencyData,
  WalletStructureData, AccountData, ClpCryptoLibTypes, ClpSecureRandom,
  ClpISecureRandom, ClpCryptoApiRandomGenerator, ClpICryptoApiRandomGenerator,
  AssetsMenagerData, HlpBlake2BConfig, HlpBlake2B, HlpHashFactory,
  ClpDigestUtilities, HlpIHash, misc, ClpIX9ECParameters, ClpIECDomainParameters,
  ClpECDomainParameters, ClpIECKeyPairGenerator, ClpECKeyPairGenerator,
  ClpIECKeyGenerationParameters, ClpIAsymmetricCipherKeyPair,
  ClpIECPrivateKeyParameters, ClpIECPublicKeyParameters,
  ClpECPrivateKeyParameters, ClpIECInterface, ClpHex, ClpCustomNamedCurves,
  ClpHMacDsaKCalculator, ECCObj

{$IFDEF ANDROID}, Androidapi.JNI.GraphicsContentViewText, Androidapi.JNI.JavaTypes,
  Androidapi.Helpers, Androidapi.JNI.Net, Androidapi.JNI.Os, Androidapi.JNI.Webkit,
  Androidapi.JNIBridge
{$ENDIF}
{$IFDEF MSWINDOWS}
  , WinApi.ShellApi

{$ENDIF};

const
  RAI_TO_RAW = '000000000000000000000000';
  MAIN_NET_WORK_THRESHOLD = 'ffffffc000000000';
  STATE_BLOCK_PREAMBLE = '0000000000000000000000000000000000000000000000000000000000000006';
  STATE_BLOCK_ZERO = '0000000000000000000000000000000000000000000000000000000000000000';

type
  TNanoBlock = record
    blockType: AnsiString;
    state: Boolean;
    send: Boolean;
    hash: ansistring;
    signed: Boolean;
    worked: Boolean;
    signature: AnsiString;
    work: AnsiString;
    blockAmount: BigInteger;
    blockAccount: AnsiString;
    blockMessage: AnsiString;
    origin: AnsiString;
    immutable: Boolean;
    timestamp: System.UInt32;
    previous: AnsiString;
    destination: AnsiString;
    balance: AnsiString;
    source: AnsiString;
    representative: AnsiString;
    account: AnsiString;
  end;

function nano_accountFromHexKey(adr: AnsiString): AnsiString;
function nano_keyFromAccount(adr: ansistring): ansistring;
implementation

const
  nano_charset = '13456789abcdefghijkmnopqrstuwxyz';

function nano_keyFromAccount(adr: ansistring): ansistring;
var chk:ansistring;
rAdr,rChk:TIntegerArray;
i:Integer;
begin
  result := adr;
 adr:=stringreplace(adr,'xrb_','',[rfReplaceAll]);
 chk:=Copy(adr,52{$IFDEF MSWINDOWS}+1{$ENDIF},100);
 adr:='1111'+Copy(adr,0,52);
 SetLength(rAdr,Length(adr));
  SetLength(rChk,Length(chk));
for I := 0 to Length(adr)-1 do
 rAdr[i]:=Pos(adr[i{$IFDEF MSWINDOWS}+1{$ENDIF}],nano_charset){$IFDEF MSWINDOWS}-1{$ENDIF};

for I := 0 to Length(chk)-1 do
 rChk[i]:=Pos(chk[i{$IFDEF MSWINDOWS}+1{$ENDIF}],nano_charset){$IFDEF MSWINDOWS}-1{$ENDIF};
result:='';
radr:=ChangeBits(radr,5,8,true);
 for i := 3 to length(rAdr)-1 do
   result:=result+inttohex(rAdr[i],2)
end;

function nano_encodeBase32(values: TIntegerArray): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(values) - 1 do
  begin
    Result := Result + nano_charset[values[i] + low(nano_charset)];
  end;
end;

function nano_addressChecksum(m: AnsiString): ansistring;
var
  Blake2b: IHash;
begin
  Blake2b := THashFactory.TCrypto.CreateBlake2B(TBlake2BConfig.Create(5));
  Blake2b.Initialize();
  Blake2b.TransformBytes(hexatotbytes(m), 0, length(m) div 2);
  Result := Blake2b.TransformFinal.ToString();
  Result := reversehexorder(result);
end;

function nano_accountFromHexKey(adr: AnsiString): AnsiString;
var
  data, chk: TIntegerArray;
begin
  Result := 'FAILED';
  chk := hexatotintegerarray(nano_addressChecksum(adr));
  adr := '303030' + adr;
  data := hexatotintegerarray(adr);                        //Copy(adr,4{$IFDEF MSWINDOWS}+1{$ENDIF},100)

  data := ChangeBits(data, 8, 5, true);
  chk := ChangeBits(chk, 8, 5, true);
   Delete(data,0,4);
  Result := 'xrb_' + nano_encodeBase32(data) + nano_encodeBase32(chk);
end;

function nano_newBlock(state: Boolean = False): TNanoBlock;
begin
  Result.state := state;
  Result.signed := false;
  Result.worked := false;
  Result.signature := '';
  Result.work := '';
  Result.blockAmount := 0;
  Result.immutable := false;
end;

function nano_getBlockHash(var block: TNanoBlock): AnsiString;
var
  Blake2b: IHash;
  toHash: AnsiString;
begin
  Blake2b := THashFactory.TCrypto.CreateBlake2B_256();
  Blake2b.Initialize();
  toHash := '';
  if block.state then
  begin
    toHash := toHash + STATE_BLOCK_PREAMBLE;
    toHash := toHash + block.account;
    toHash := toHash + block.previous;
    toHash := toHash + block.representative;
    toHash := toHash + block.balance;
    if block.blockType = 'send' then
      toHash := toHash + block.destination;
    if block.blockType = 'receive' then
      toHash := toHash + block.source;
    if block.blockType = 'open' then
      toHash := toHash + block.source;
    if block.blockType = 'change' then
      toHash := toHash + STATE_BLOCK_ZERO;
  end
  else
  begin
    if block.blockType = 'send' then
    begin
      toHash := toHash + block.previous;
      toHash := toHash + block.destination;
      toHash := toHash + block.balance;
    end;
    if block.blockType = 'receive' then
    begin
      toHash := toHash + block.previous;
      toHash := toHash + block.source;
    end;
    if block.blockType = 'open' then
    begin
      toHash := toHash + block.source;
      toHash := toHash + block.representative;
      toHash := toHash + block.account;
    end;
    if block.blockType = 'change' then
    begin
      toHash := toHash + block.previous;
      toHash := toHash + block.representative;
    end;
  end;
  Blake2b.TransformBytes(hexatotbytes(toHash), 0, Length(toHash) div 2);
  Result := Blake2b.TransformFinal.ToString();
  block.hash := Result;
end;

procedure nano_setSendParameters(var block: TNanoBlock; previousBlockHash, destinationAccount, balanceRemaining: AnsiString);
var
  accKey: ansistring;
begin

  if (not IsHex(previousBlockHash)) then
    raise Exception.Create('Invalid previous block hash');
  try
    accKey := nano_keyFromAccount(destinationAccount);
  except
    on E: Exception do
      raise Exception.Create('Invalid dest address');
  end;
  block.previous := previousBlockHash;
  block.destination := accKey;
  block.balance := balanceRemaining;
  block.blockType := 'send';
end;

procedure nano_setReceiveParameters(var block: TNanoBlock; previousBlockHash, sourceBlockHash: AnsiString);
begin
  if (not IsHex(previousBlockHash)) then
    raise Exception.Create('Invalid previous block hash');
  if (not IsHex(sourceBlockHash)) then
    raise Exception.Create('Invalid source block hash');

  block.previous := previousBlockHash;
  block.source := sourceBlockHash;
  block.blockType := 'receive';

end;

procedure nano_setStateParameters(var block: TNanoBlock; newAccount, representativeAccount, curBalance: AnsiString);
begin

  try
    block.Account := nano_keyFromAccount(newAccount);

  except
    on E: Exception do
      raise Exception.Create('Invalid address');
  end;
  try
    block.representative := nano_keyFromAccount(representativeAccount);

  except
    on E: Exception do
      raise Exception.Create('Invalid representative address');
  end;
  block.balance := curBalance;
end;

procedure nano_setOpenParameters(var block: TNanoBlock; sourceBlockHash, newAccount, representativeAccount: AnsiString);
begin
  if (not IsHex(sourceBlockHash)) then
    raise Exception.Create('Invalid source block hash');

  if representativeAccount <> '' then
    block.representative := nano_keyFromAccount(representativeAccount)
  else
    block.representative := block.account;
  block.source := sourceBlockHash;
  if block.State then
    block.previous := STATE_BLOCK_ZERO;
  block.blockType := 'open';

end;

procedure nano_setChangeParameters(var block: TNanoBlock; previousBlockHash, representativeAccount: AnsiString);
begin
  if not IsHex(previousBlockHash) then
    raise Exception.Create('Invalid previous block hash');
  block.representative := nano_keyFromAccount(representativeAccount);
  block.previous := previousBlockHash;
  block.blockType := 'change';

end;

procedure nano_setSignature(var block: TNanoBlock; hex: ansistring);
begin
  block.signature := hex;
  block.signed := True;
end;

function nano_getPrevious(block: TNanoBlock): AnsiString;
begin
  if block.blockType = 'open' then
    Exit(block.account);
  result := block.previous;
end;

function nano_checkWork(block: TNanoBlock; work: AnsiString; blockHash: AnsiString = ''): Boolean;
var
  t, t2: TBytes;
var
  Blake2b: IHash;
  toHash: AnsiString;
begin
  result := false;
  Blake2b := THashFactory.TCrypto.CreateBlake2B_256();
  Blake2b.Initialize();
  toHash := '';
  if blockHash = '' then
    blockHash := nano_getPrevious(block);
  t := hexatotbytes(MAIN_NET_WORK_THRESHOLD);
  toHash := work; //reserve?
  toHash := toHash + blockHash;
  Blake2b.TransformBytes(hexatotbytes(toHash), 0, Length(toHash) div 2);
  t2 := hexatotbytes(Blake2b.TransformFinal.ToString());    // reserve?
  if t2[0] = t[0] then
    if t2[1] = t[1] then
      if t2[2] = t[2] then
        if t2[3] >= t[3] then
          result := True;
end;

procedure nano_setWork(var block: TNanoBlock; hex: ansistring);
begin
  if not nano_checkWork(block, hex) then
    raise Exception.Create('Work not valid for block');
  block.work := hex;
  block.worked := True;
end;

procedure nano_setAccount(var block: TNanoBlock; acc: AnsiString);
begin
  block.blockAccount := acc;
  if block.blockType = 'send' then
    block.origin := acc;
end;

procedure nano_setOrigin(var block: TNanoBlock; acc: AnsiString);
begin
  if (block.blockType = 'receive') or (block.blockType = 'open') then
    block.origin := acc;
end;

procedure nano_setTimestamp(var block: TNanoBlock; millis: System.UInt64);
begin
  block.timestamp := millis;
end;

function nano_getOrigin(block: TNanoBlock): AnsiString;
begin
  if (block.blockType = 'receive') or (block.blockType = 'open') then
    Exit(block.origin);
  if (block.blockType = 'send') then
    Exit(block.blockAccount);
  result := '';
end;

function nano_getDestination(block: TNanoBlock): AnsiString;
begin
  if (block.blockType = 'send') then
    Exit(nano_accountFromHexKey(block.destination));
  if (block.blockType = 'receive') or (block.blockType = 'open') then
    Exit(block.blockAccount);

end;

function nano_getRepresentative(block: TNanoBlock): ansistring;
begin
  if (block.state) or (block.blockType = 'change') or (block.blockType = 'open') then
    Exit(nano_accountFromHexKey(block.representative))
  else
    result := '';

end;

function nano_isReady(block: TNanoBlock): Boolean;
begin
  result := block.signed and block.worked;
end;

procedure nano_changePrevious(var block: TNanoBlock; newPrevious: AnsiString);
begin
  if block.blockType = 'open' then
    raise Exception.Create('Open has no previous block');
  if block.blockType = 'receive' then
  begin
    nano_setReceiveParameters(block, newPrevious, block.source);
    nano_getBlockHash(block);
    Exit;
  end;
  if block.blockType = 'send' then
  begin
    nano_setSendParameters(block, newPrevious, block.destination, block.balance);  // api.setSendParameters(newPrevious, destination, stringFromHex(balance).replace(RAI_TO_RAW, ''))
    nano_getBlockHash(block);
    Exit;
  end;
  if block.blockType = 'change' then
  begin
    nano_setChangeParameters(block, newPrevious, block.representative);
    nano_getBlockHash(block);
    Exit;
  end;
  raise Exception.Create('Invalid block type');
end;

function nano_getJSONBlock(block: TNanoBlock): AnsiString;
var
  obj: TjsonObject;
begin
  if not block.signed then
    raise Exception.Create('Block not signed');

  obj := TJSONObject.Create();
  if block.state then
  begin
    obj.AddPair(TJSONPair.Create('type', 'state'));
    if block.blockType = 'open' then
      obj.AddPair(TJSONPair.Create('previous', STATE_BLOCK_ZERO))
    else
      obj.AddPair(TJSONPair.Create('previous', block.previous));

    obj.AddPair(TJSONPair.Create('account', nano_accountFromHexKey(block.account)));
    obj.AddPair(TJSONPair.Create('representative', nano_accountFromHexKey(block.representative + block.account)));
    obj.AddPair(TJSONPair.Create('balance', BigInteger.Parse('0x0' + block.balance).ToString(10)));
    if block.blockType = 'send' then
      obj.AddPair(TJSONPair.Create('link', block.destination));
    if block.blockType = 'receive' then
      obj.AddPair(TJSONPair.Create('link', block.source));
    if block.blockType = 'open' then
      obj.AddPair(TJSONPair.Create('link', block.source));
    if block.blockType = 'change' then
      obj.AddPair(TJSONPair.Create('link', STATE_BLOCK_ZERO));
  end
  else
  begin
    obj.AddPair(TJSONPair.Create('type', block.blockType));
    if block.blockType = 'send' then
    begin
      obj.AddPair(TJSONPair.Create('previous', block.previous));
      obj.AddPair(TJSONPair.Create('destination', nano_accountFromHexKey(block.destination)));
      obj.AddPair(TJSONPair.Create('balance', block.balance));
    end;
    if block.blockType = 'receive' then
    begin
      obj.AddPair(TJSONPair.Create('source', block.source));
      obj.AddPair(TJSONPair.Create('previous', block.previous));
    end;
    if block.blockType = 'open' then
    begin
      obj.AddPair(TJSONPair.Create('source', block.source));
      obj.AddPair(TJSONPair.Create('representative', nano_accountFromHexKey(block.representative + block.account)));
      obj.AddPair(TJSONPair.Create('account', nano_accountFromHexKey(block.account)));
    end;
    if block.blockType = 'change' then
    begin
      obj.AddPair(TJSONPair.Create('previous', block.previous));
      obj.AddPair(TJSONPair.Create('representative', nano_accountFromHexKey(block.representative)));
    end;
  end;
  obj.AddPair(TJSONPair.Create('work', block.work));
  obj.AddPair(TJSONPair.Create('signature', block.signature));
  result := obj.ToJSON;
  obj.Free;
end;

function nano_buildFromJSON(json, prev: ansistring): TNanoBlock;
var
  obj, prevObj: TJsonObject;
var
  state: string;
begin
  result := nano_newBlock(false);
  obj := TJSONObject.ParseJSONValue(TEncoding.ASCII.GetBytes(json), 0) as TJSONObject;
  prevObj := TJSONObject.ParseJSONValue(TEncoding.ASCII.GetBytes(prev), 0) as TJSONObject;
  state := obj.GetValue('state').Value;

  Result.state := StrToBoolDef(state, False) or False;
  Result.blockType := obj.GetValue('type').Value;
  if Result.state then
  begin
    Result.send := false;
    if prevObj <> nil then
    begin
      if prevObj.GetValue('type').Value <> 'state' then
        Result.send := BigInteger.Parse('0x0' + prevObj.GetValue('balance').Value) > BigInteger.Parse('0x0' + obj.GetValue('balance').Value);

    end;
    Result.previous := obj.GetValue('previous').Value;
    Result.balance := BigInteger.Parse(obj.GetValue('balance').Value).ToString(16);
    Result.account := nano_keyFromAccount(obj.GetValue('account').Value);
    Result.representative := nano_keyFromAccount(obj.GetValue('representative').Value);
    if Result.send then
    begin
      Result.blockType := 'send';
      Result.destination := obj.GetValue('link').Value;
    end
    else
    begin
      if obj.GetValue('link').Value = STATE_BLOCK_ZERO then
        Result.blockType := 'change'
      else
      begin
        if Result.previous = STATE_BLOCK_ZERO then
        begin
          Result.blockType := 'open';
          Result.source := obj.GetValue('link').Value;
        end
        else
        begin
          Result.blockType := 'receive';
          Result.source := obj.GetValue('link').Value;
        end;
      end;

    end;

  end
  else
  begin
    if Result.blockType = 'send' then
    begin
      Result.previous := obj.GetValue('previous').Value;
      Result.destination := nano_keyFromAccount(obj.GetValue('destination').Value);
      Result.balance := obj.GetValue('balance').Value;
    end;
    if Result.blockType = 'receive' then
    begin
      Result.previous := obj.GetValue('previous').Value;
      Result.source := obj.GetValue('source').Value;

    end;
    if Result.blockType = 'open' then
    begin
      Result.source := obj.GetValue('source').Value;
      Result.representative := nano_keyFromAccount(obj.GetValue('representative').Value);
      Result.account := nano_keyFromAccount(obj.GetValue('account').Value);
    end;
    if Result.blockType = 'change' then
    begin
      Result.previous := obj.GetValue('previous').Value;
      Result.representative := nano_keyFromAccount(obj.GetValue('representative').Value)

    end;
  end;
  Result.signature := obj.GetValue('signature').Value;
  Result.work := obj.GetValue('work').Value;
  if Result.work <> '' then
    Result.worked := true;
  if Result.signature <> '' then
    Result.signed := true;
  Result.hash := nano_getBlockHash(result);
end;

function nano_pubFromPriv(sk: AnsiString): ansistring;
var
  ecc: TECCEncSign;
begin
  ecc := TECCEncSign.Create(nil);
  ecc.ECCType := cc25519;
  ecc.outputFormat := hexa;
  ecc.Unicode := noUni;
  ecc.NaCl := naclno;
  ecc.PrivateKey := '0000000000000000000000000000000000000000000000000000000000000000';
  ecc.Sign('');
end;

end.

