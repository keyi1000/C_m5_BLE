#include <M5Unified.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>

// BLE関連のグローバル変数
BLEServer* pServer = nullptr;
bool isConnected = false;
uint32_t connectionCount = 0;
bool lastState = false;

// 時間計測用
unsigned long startTime = 0;
unsigned long lastUpdate = 0;
unsigned long lastGC = 0;

// BLEサーバーコールバッククラス
class MyServerCallbacks: public BLEServerCallbacks {
  void onConnect(BLEServer* pServer) {
    isConnected = true;
    connectionCount++;
    Serial.printf("Device connected (total: %d)\n", connectionCount);
  }

  void onDisconnect(BLEServer* pServer) {
    isConnected = false;
    Serial.println("Device disconnected");
    connectionCount--;
    // 切断されたら再度アドバタイズ開始
    BLEDevice::startAdvertising();
  }
};

// 画面を指定色でクリア
void fillScreen(uint32_t color) {
  M5.Display.fillScreen(color);
}

// ラベル表示用関数
void drawLabel(const char* text, int x, int y, int textSize, uint32_t fgColor, uint32_t bgColor) {
  M5.Display.setTextColor(fgColor, bgColor);
  M5.Display.setTextSize(textSize);
  M5.Display.setCursor(x, y);
  M5.Display.print(text);
}

// ステータス表示を更新
void updateStatus(const char* status) {
  drawLabel(status, 10, 20, 2, TFT_WHITE, TFT_BLACK);
  Serial.println(status);
}

// 情報表示を更新
void updateInfo(const char* info) {
  drawLabel(info, 10, 60, 2, TFT_GREEN, TFT_BLACK);
}

// データ表示を更新
void updateData(const char* data) {
  drawLabel(data, 10, 100, 2, TFT_YELLOW, TFT_BLACK);
}

void setup() {
  // M5Stackの初期化
  M5.begin();
  M5.Display.setRotation(1);
  fillScreen(TFT_BLACK);
  
  updateStatus("Starting...");
  delay(1000);
  
  try {
    // BLE初期化ステップ
    updateStatus("Init BLE...");
    delay(1000);
    
    // BLEデバイスの初期化
    BLEDevice::init("M5Stack-BLE");
    delay(1000);
    
    updateStatus("Activating...");
    delay(1000);
    
    // BLEサーバーの作成
    pServer = BLEDevice::createServer();
    pServer->setCallbacks(new MyServerCallbacks());
    delay(1000);
    
    updateStatus("Set IRQ...");
    delay(1000);
    
    // BLEサービスの作成(UUIDは例)
    BLEService *pService = pServer->createService("4fafc201-1fb5-459e-8fcc-c5c9c331914b");
    
    // BLE Characteristicの作成(オプション - データ送受信用)
    BLECharacteristic *pCharacteristic = pService->createCharacteristic(
                                           "beb5483e-36e1-4688-b7f5-ea07361b26a8",
                                           BLECharacteristic::PROPERTY_READ |
                                           BLECharacteristic::PROPERTY_WRITE
                                         );
    pCharacteristic->setValue("Hello BLE");
    pService->start();
    
    updateStatus("Advertising...");
    delay(1000);
    
    // アドバタイズの開始
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID("4fafc201-1fb5-459e-8fcc-c5c9c331914b");
    pAdvertising->setScanResponse(true);
    pAdvertising->setMinPreferred(0x06);  // iPhone接続の問題を解決するのに役立つ
    pAdvertising->setMinPreferred(0x12);
    BLEDevice::startAdvertising();
    
    updateStatus("BLE Ready!");
    updateInfo("Device: M5Stack-BLE");
    fillScreen(TFT_BLUE);
    updateStatus("BLE Ready!");
    updateInfo("Device: M5Stack-BLE");
    
    Serial.println("BLE Ready - waiting for connection");
    
    startTime = millis();
    lastUpdate = millis();
    lastGC = millis();
    
  } catch (...) {
    updateStatus("ERROR");
    updateInfo("Init Failed");
    fillScreen(TFT_RED);
    Serial.println("Error: BLE initialization failed");
  }
}

void loop() {
  M5.update();
  
  unsigned long currentTime = millis();
  
  // 接続状態が変化したら画面更新
  if (isConnected != lastState) {
    if (isConnected) {
      fillScreen(TFT_GREEN);  // 緑 = 接続
      updateStatus("Connected!");
      char buf[32];
      sprintf(buf, "Connections: %d", connectionCount);
      updateInfo(buf);
    } else {
      fillScreen(TFT_BLUE);  // 青 = 待機
      updateStatus("Disconnected");
      updateInfo("Waiting...");
    }
    lastState = isConnected;
  }
  
  // 5秒ごとに経過時間を画面表示
  if (currentTime - lastUpdate >= 5000) {
    char buf[32];
    sprintf(buf, "Time: %lus", (currentTime - startTime) / 1000);
    updateData(buf);
    lastUpdate = currentTime;
  }
  
  // 10秒ごとにメモリ情報をシリアル出力
  if (currentTime - lastGC >= 10000) {
    Serial.printf("Free heap: %d bytes\n", ESP.getFreeHeap());
    lastGC = currentTime;
  }
  
  delay(200);
}