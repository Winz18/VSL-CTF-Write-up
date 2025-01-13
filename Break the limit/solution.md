![image](https://github.com/user-attachments/assets/bf7d4900-12b8-4c03-acd9-8d4bcf0cdb15)

Challenge là một webapp với các chức năng thông thường như đăng ký, đăng nhập, chỉnh sửa profile người dùng,...Tuy nhiên khi đi vào phân tích source code ở tính năng edit profile, ta sẽ thấy có một vấn đề bảo mật.
Ứng dụng đã xử lý không an toàn trong việc hiển thị nội dung log từ các hoạt động của user như đổi mật khẩu, tên đăng nhập.

![image](https://github.com/user-attachments/assets/f81d6840-a90c-4641-a431-d21bccb4d760)
![image](https://github.com/user-attachments/assets/841d11ee-8fa7-4ef7-838b-3ca2b7f33305)
![image](https://github.com/user-attachments/assets/c69b9133-8f6b-44d1-a6c8-7a857b9c0d65)

### LFI2RCE

Trong PHP, khi bạn sử dụng include() hoặc require() để nhúng tệp từ người dùng hoặc bất kỳ đầu vào nào, bạn có nguy cơ gặp phải lỗ hổng Local File Inclusion (LFI). Điều này xảy ra nếu một người tấn công có thể thay đổi tham số mà bạn sử dụng để chỉ định đường dẫn tệp. Và nếu trong file được include có chứa code PHP thì nó sẽ được thực thi => ta có thể RCE để đọc flag. Mục đích chính của author là lợi dụng việc ghi log để truyền code PHP vào. Do đó author có tăng độ khó cho challenge lên bằng cách kiểm tra độ dài username khi đổi (xem hình trên). Vì vậy ta cần phải chia nhỏ payload ra nhiều đoạn rồi nối lại. Payload sẽ thực thi lệnh để in flag trong /flag.txt và ta có thể xem nó khi server include vào.

### Bug trong triển khai ý tưởng

Ý tưởng của author cũng khá thú vị nhưng khi triển khai làm app thì đã mắc 1 vấn đề như sau: ứng dụng chỉ kiểm tra đội dài username khi thực hiện edit profile nhưng lại không kiểm tra điều đó khi user đăng ký account. Thêm vào đó, tên file được include bằng cách ghép chuỗi.

![image](https://github.com/user-attachments/assets/3e886961-99b1-480e-bf96-b57642d91aaa)

Dễ thấy, ta có thể đọc /flag.txt mà không cần RCE bằng cách path traversal trong username khi đăng ký lần đầu. Với các ký tự `../`, ta có thể dễ dàng di chuyển đến vị trí đặt flag. Và khi vào tính năng xem log trong profile, server sẽ include flag vào (xem ảnh chứa code html ở trên). 

![image](https://github.com/user-attachments/assets/bfc0f88e-73a3-4886-81dc-3d893c17588f)







