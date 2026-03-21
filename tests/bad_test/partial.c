#include <iostream>
#include <vector>
#include <cstring>

class UserData {
private:
    char *buffer;
    int size;

public:
    UserData(int s) {
        size = s;
        buffer = new char[size];
    }

    ~UserData() {
        delete[] buffer;
    }

    void copyInput(const char *input) {
        // Missing bounds validation
        strcpy(buffer, input);
    }

    char getFirstChar() {
        if (buffer != nullptr) {
            return buffer[0];
        }
        return '\0';
    }
};

class DataProcessor {
private:
    std::vector<UserData*> records;

public:
    void addRecord(UserData* record) {
        records.push_back(record);
    }

    void processRecords() {
        for (size_t i = 0; i < records.size(); i++) {

            UserData *rec = records[i];

            // Potential null dereference
            if (rec != nullptr) {
                char c = rec->getFirstChar();
                std::cout << "First char: " << c << std::endl;
            }
        }
    }

    ~DataProcessor() {
        // Manual cleanup
        for (size_t i = 0; i < records.size(); i++) {
            delete records[i];
        }
    }
};

void unsafeInputHandler() {

    char inputBuffer[64];

    std::cout << "Enter a string: ";
    std::cin >> inputBuffer;  // no bounds check

    UserData *data = new UserData(32);

    // Possible overflow depending on input size
    data->copyInput(inputBuffer);

    DataProcessor processor;

    processor.addRecord(data);

    processor.processRecords();
}

void pointerExperiment() {

    int *ptr = nullptr;

    if (rand() % 2) {
        ptr = new int(42);
    }

    // Conditional dereference
    if (ptr) {
        std::cout << *ptr << std::endl;
    }

    delete ptr;
}

void memoryFragmentationTest() {

    std::vector<char*> memoryPool;

    for (int i = 0; i < 10; i++) {
        char *block = new char[16];
        memset(block, 'A', 15);
        block[15] = '\0';

        memoryPool.push_back(block);
    }

    for (size_t i = 0; i < memoryPool.size(); i++) {
        std::cout << memoryPool[i] << std::endl;
    }

    for (size_t i = 0; i < memoryPool.size(); i++) {
        delete[] memoryPool[i];
    }
}

int main() {

    std::cout << "=== Running Partial Vulnerability Demo ===" << std::endl;

    unsafeInputHandler();

    pointerExperiment();

    memoryFragmentationTest();

    std::cout << "Program finished." << std::endl;

    return 0;
}
