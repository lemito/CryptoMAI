#include <iostream>
#define BOOST_ASIO_STANDALONE
#include <boost/asio.hpp>

int main() {
  std::mutex m;
  boost::asio::thread_pool pool(std::thread::hardware_concurrency());
  boost::asio::post(pool, [&] {
    std::lock_guard l(m);
    std::cout << "1)Task executed by thread: " << std::this_thread::get_id()
              << std::endl;
  });
  boost::asio::post(pool, [&] {
    std::lock_guard l(m);
    std::cout << "2)Task executed by thread: " << std::this_thread::get_id()
              << std::endl;
  });
  boost::asio::post(pool, [&] {
    std::lock_guard l(m);
    std::cout << "3)Task executed by thread: " << std::this_thread::get_id()
              << std::endl;
  });
  boost::asio::post(pool, [&] {
    std::lock_guard l(m);
    std::cout << "4)Task executed by thread: " << std::this_thread::get_id()
              << std::endl;
  });
  pool.join();
  return 0;
}