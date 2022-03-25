#include <iostream>
#include <string>

#include "rcrypt.h"
#include "Hex.h"

#include <chrono>
#include <vector>

int main() {
    system("clear");

    std::string *enc = new std::string("Some text or info here.");


    //
    // 512
    //

    {
        std::string key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        std::string *ex = new std::string(*enc);

        // Encryption

        {
            std::vector<double> data1e;

            for (int i = 0; i < 3000; i++) {
                std::string *ence = new std::string(*enc);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt512_enc(key, ence);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1e.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete ence;
            }

            double mean = 0;

            for (int p = 0; p < data1e.size(); p++) {
                mean += data1e[p] / data1e.size();
            }

            Red::rcrypt512_enc(key, ex);

            std::cout << "Encryption(512):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Enc(hex): " << *Red::GetHexArray(*ex) << std::endl;
            std::cout << "\n" << std::endl;
        }


        // Decryption

        {
            std::vector<double> data1d;

            for (int i = 0; i < 3000; i++) {
                std::string *decd = new std::string(*ex);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt512_dec(key, decd);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1d.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete decd;
            }

            double mean = 0;

            for (int p = 0; p < data1d.size(); p++) {
                mean += data1d[p] / data1d.size();
            }

            Red::rcrypt512_dec(key, ex);

            std::cout << "Decryption(512):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Dec(str): " << *ex << std::endl;
            std::cout << "\n" << std::endl;
        }


        // Hash

        {
            std::vector<double> data1h;

            for (int i = 0; i < 3000; i++) {
                std::string *hashe = new std::string(*enc);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt512_hash(key, *hashe);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1h.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete hashe;
            }

            double mean = 0;

            for (int p = 0; p < data1h.size(); p++) {
                mean += data1h[p] / data1h.size();
            }

            std::string *hs = Red::rcrypt512_hash(key, *ex);

            std::cout << "Hash(512):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Hashed: " << *hs << std::endl;
            std::cout << "\n" << std::endl;

            delete hs;
        }

        delete ex;
    }

    //
    // 1024
    //

    {
        std::string key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        std::string *ex = new std::string(*enc);

        // Encryption

        {
            std::vector<double> data1e;

            for (int i = 0; i < 3000; i++) {
                std::string *ence = new std::string(*enc);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt1024_enc(key, ence);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1e.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete ence;
            }

            double mean = 0;

            for (int p = 0; p < data1e.size(); p++) {
                mean += data1e[p] / data1e.size();
            }

            Red::rcrypt1024_enc(key, ex);

            std::cout << "Encryption(1024):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Enc(hex): " << *Red::GetHexArray(*ex) << std::endl;
            std::cout << "\n" << std::endl;
        }


        // Decryption

        {
            std::vector<double> data1d;

            for (int i = 0; i < 3000; i++) {
                std::string *decd = new std::string(*ex);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt1024_dec(key, decd);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1d.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete decd;
            }

            double mean = 0;

            for (int p = 0; p < data1d.size(); p++) {
                mean += data1d[p] / data1d.size();
            }

            Red::rcrypt1024_dec(key, ex);

            std::cout << "Decryption(1024):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Dec(str): " << *ex << std::endl;
            std::cout << "\n" << std::endl;
        }


        // Hash

        {
            std::vector<double> data1h;

            for (int i = 0; i < 3000; i++) {
                std::string *hashe = new std::string(*enc);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt1024_hash(key, *hashe);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1h.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete hashe;
            }

            double mean = 0;

            for (int p = 0; p < data1h.size(); p++) {
                mean += data1h[p] / data1h.size();
            }

            std::string *hs = Red::rcrypt1024_hash(key, *ex);

            std::cout << "Hash(1024):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Hashed: " << *hs << std::endl;
            std::cout << "\n" << std::endl;

            delete hs;
        }

        delete ex;
    }

    //
    // 1536
    //

    {
        std::string key = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        std::string *ex = new std::string(*enc);

        // Encryption

        {
            std::vector<double> data1e;

            for (int i = 0; i < 3000; i++) {
                std::string *ence = new std::string(*enc);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt1536_enc(key, ence);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1e.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete ence;
            }

            double mean = 0;

            for (int p = 0; p < data1e.size(); p++) {
                mean += data1e[p] / data1e.size();
            }

            Red::rcrypt1536_enc(key, ex);

            std::cout << "Encryption(1536):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Enc(hex): " << *Red::GetHexArray(*ex) << std::endl;
            std::cout << "\n" << std::endl;
        }


        // Decryption

        {
            std::vector<double> data1d;

            for (int i = 0; i < 3000; i++) {
                std::string *decd = new std::string(*ex);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt1536_dec(key, decd);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1d.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete decd;
            }

            double mean = 0;

            for (int p = 0; p < data1d.size(); p++) {
                mean += data1d[p] / data1d.size();
            }

            Red::rcrypt1536_dec(key, ex);

            std::cout << "Decryption(1536):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Dec(str): " << *ex << std::endl;
            std::cout << "\n" << std::endl;
        }


        // Hash

        {
            std::vector<double> data1h;

            for (int i = 0; i < 3000; i++) {
                std::string *hashe = new std::string(*enc);

                auto start = std::chrono::system_clock::now();
                Red::rcrypt1536_hash(key, *hashe);
                auto duration = std::chrono::system_clock::now() - start;

                if (i >= 60) {
                    data1h.push_back(std::chrono::duration_cast<std::chrono::microseconds>(duration).count() / 1000000.0);
                }

                delete hashe;
            }

            double mean = 0;

            for (int p = 0; p < data1h.size(); p++) {
                mean += data1h[p] / data1h.size();
            }

            std::string *hs = Red::rcrypt1536_hash(key, *ex);

            std::cout << "Hash(1536):" << std::endl;
            std::cout << "av: " << mean << " seconds, ~" << 1 / mean << " Hash/sec" << std::endl;
            std::cout << "Hashed: " << *hs << std::endl;
            std::cout << "\n" << std::endl;

            delete hs;
        }

        delete ex;
    }

    delete enc;

    return 0;
}
