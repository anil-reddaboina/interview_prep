
# Java Interview Questions for Senior Software Engineer/Architect

## 1. Open Close Principle, Abstract Pattern, and Strategy Pattern

### Open Close Principle (OCP)
**Definition**: Software entities should be open for extension but closed for modification.

**Key Points**:
- **Open for Extension**: New functionality can be added through new classes, methods, or modules
- **Closed for Modification**: Existing code should not be modified to add new features
- **Benefits**: Reduces risk of breaking existing functionality, improves maintainability

**Example**:
```java
// Violation of OCP
class PaymentProcessor {
    public void processPayment(String type) {
        if (type.equals("credit")) {
            // Credit card logic
        } else if (type.equals("debit")) {
            // Debit card logic
        }
        // Adding new payment type requires modification
    }
}

// Following OCP
interface PaymentStrategy {
    void processPayment();
}

class CreditCardPayment implements PaymentStrategy {
    public void processPayment() {
        // Credit card implementation
    }
}

class DebitCardPayment implements PaymentStrategy {
    public void processPayment() {
        // Debit card implementation
    }
}

class PaymentProcessor {
    private PaymentStrategy strategy;
    
    public void setStrategy(PaymentStrategy strategy) {
        this.strategy = strategy;
    }
    
    public void processPayment() {
        strategy.processPayment();
    }
}
```

### Abstract Pattern
**Purpose**: Provides an interface for creating families of related objects without specifying their concrete classes.

**Use Cases**:
- When a system should be independent of how its products are created, composed, and represented
- When a system should be configured with one of multiple families of products
- When a family of related product objects is designed to be used together

**Example**:
```java
interface GUIFactory {
    Button createButton();
    Checkbox createCheckbox();
}

class WinFactory implements GUIFactory {
    public Button createButton() { return new WinButton(); }
    public Checkbox createCheckbox() { return new WinCheckbox(); }
}

class MacFactory implements GUIFactory {
    public Button createButton() { return new MacButton(); }
    public Checkbox createCheckbox() { return new MacCheckbox(); }
}
```

### Strategy Pattern
**Purpose**: Defines a family of algorithms, encapsulates each one, and makes them interchangeable.

**Benefits**:
- Eliminates conditional statements
- Provides runtime algorithm selection
- Easy to add new strategies
- Follows Single Responsibility Principle

**Example**:
```java
interface SortingStrategy {
    void sort(int[] array);
}

class BubbleSort implements SortingStrategy {
    public void sort(int[] array) {
        // Bubble sort implementation
    }
}

class QuickSort implements SortingStrategy {
    public void sort(int[] array) {
        // Quick sort implementation
    }
}

class Sorter {
    private SortingStrategy strategy;
    
    public void setStrategy(SortingStrategy strategy) {
        this.strategy = strategy;
    }
    
    public void sort(int[] array) {
        strategy.sort(array);
    }
}
```

## 2. Builder Pattern (Creational Pattern) and Design Pattern Use Cases

### Builder Pattern
**Purpose**: Constructs complex objects step by step, allowing construction of different representations using the same construction code.

**When to Use**:
- Object has many optional parameters
- Object creation is complex
- Immutable object creation
- Fluent API design

**Example**:
```java
public class User {
    private final String firstName;
    private final String lastName;
    private final String email;
    private final String phone;
    private final String address;
    
    private User(UserBuilder builder) {
        this.firstName = builder.firstName;
        this.lastName = builder.lastName;
        this.email = builder.email;
        this.phone = builder.phone;
        this.address = builder.address;
    }
    
    public static class UserBuilder {
        private String firstName;
        private String lastName;
        private String email;
        private String phone;
        private String address;
        
        public UserBuilder(String firstName, String lastName) {
            this.firstName = firstName;
            this.lastName = lastName;
        }
        
        public UserBuilder email(String email) {
            this.email = email;
            return this;
        }
        
        public UserBuilder phone(String phone) {
            this.phone = phone;
            return this;
        }
        
        public UserBuilder address(String address) {
            this.address = address;
            return this;
        }
        
        public User build() {
            return new User(this);
        }
    }
}

// Usage
User user = new User.UserBuilder("John", "Doe")
    .email("john@example.com")
    .phone("123-456-7890")
    .build();
```

### Design Pattern Use Cases

**Creational Patterns**:
- **Singleton**: Database connections, logging, configuration management
- **Factory Method**: Creating objects without specifying exact classes
- **Abstract Factory**: Creating families of related objects
- **Builder**: Complex object construction with many optional parameters
- **Prototype**: Creating objects by cloning existing instances

**Structural Patterns**:
- **Adapter**: Integrating incompatible interfaces
- **Bridge**: Decoupling abstraction from implementation
- **Composite**: Treating individual and composite objects uniformly
- **Decorator**: Adding responsibilities to objects dynamically
- **Facade**: Providing simplified interface to complex subsystem
- **Flyweight**: Sharing common parts of state between objects
- **Proxy**: Controlling access to objects

**Behavioral Patterns**:
- **Chain of Responsibility**: Passing requests along handler chain
- **Command**: Encapsulating requests as objects
- **Iterator**: Accessing elements without exposing internal structure
- **Mediator**: Reducing coupling between components
- **Observer**: Notifying objects of state changes
- **State**: Changing object behavior when state changes
- **Strategy**: Defining algorithm family and making them interchangeable
- **Template Method**: Defining algorithm skeleton in superclass
- **Visitor**: Adding operations without changing classes

## 3. Hashtable vs ConcurrentHashMap Differences

### Hashtable
**Characteristics**:
- **Thread Safety**: Synchronized at method level (legacy)
- **Performance**: Poor due to coarse-grained locking
- **Null Handling**: Doesn't allow null keys or values
- **Iteration**: Fail-fast iterators (ConcurrentModificationException)
- **Locking**: Single lock for entire table

**Example**:
```java
Hashtable<String, String> table = new Hashtable<>();
table.put("key", "value"); // Synchronized
// table.put(null, "value"); // Throws NullPointerException
```

### ConcurrentHashMap
**Characteristics**:
- **Thread Safety**: Fine-grained locking using segments/buckets
- **Performance**: Better than Hashtable due to reduced lock contention
- **Null Handling**: Doesn't allow null keys or values
- **Iteration**: Weakly consistent iterators (no ConcurrentModificationException)
- **Locking**: Multiple locks for different segments

**Key Features**:
- **Segment-based locking**: Only locks specific segments during operations
- **Read operations**: No locking required
- **Write operations**: Lock only affected segment
- **Scalability**: Better performance with multiple threads

**Example**:
```java
ConcurrentHashMap<String, String> map = new ConcurrentHashMap<>();
map.put("key", "value"); // Thread-safe without external synchronization
// map.put(null, "value"); // Throws NullPointerException

// Atomic operations
map.putIfAbsent("key", "newValue");
map.replace("key", "oldValue", "newValue");
```

**Performance Comparison**:
```java
// Hashtable - single lock
synchronized void put(K key, V value) {
    // Entire table is locked
}

// ConcurrentHashMap - segment-based locking
void put(K key, V value) {
    int hash = hash(key);
    int segment = hash % segments.length;
    synchronized(segments[segment]) {
        // Only this segment is locked
    }
}
```

**When to Use**:
- **Hashtable**: Legacy code, simple single-threaded scenarios
- **ConcurrentHashMap**: High-concurrency applications, modern Java applications

## 4. Making ArrayList Read-Only

### Multiple Approaches

**1. Collections.unmodifiableList()**
```java
List<String> originalList = new ArrayList<>();
originalList.add("item1");
originalList.add("item2");

List<String> readOnlyList = Collections.unmodifiableList(originalList);
// readOnlyList.add("item3"); // Throws UnsupportedOperationException
// readOnlyList.remove(0); // Throws UnsupportedOperationException
```

**2. Arrays.asList()**
```java
List<String> readOnlyList = Arrays.asList("item1", "item2", "item3");
// readOnlyList.add("item4"); // Throws UnsupportedOperationException
```

**3. List.of() (Java 9+)**
```java
List<String> readOnlyList = List.of("item1", "item2", "item3");
// readOnlyList.add("item4"); // Throws UnsupportedOperationException
```

**4. Custom Read-Only Wrapper**
```java
public class ReadOnlyArrayList<E> extends ArrayList<E> {
    public ReadOnlyArrayList(Collection<? extends E> c) {
        super(c);
    }
    
    @Override
    public boolean add(E e) {
        throw new UnsupportedOperationException("Read-only list");
    }
    
    @Override
    public boolean remove(Object o) {
        throw new UnsupportedOperationException("Read-only list");
    }
    
    @Override
    public E remove(int index) {
        throw new UnsupportedOperationException("Read-only list");
    }
    
    // Override other modification methods similarly
}
```

**5. Immutable List with Guava**
```java
// Requires Google Guava library
List<String> readOnlyList = ImmutableList.of("item1", "item2", "item3");
```

**Best Practices**:
- Use `List.of()` for Java 9+ (most efficient)
- Use `Collections.unmodifiableList()` for Java 8 and below
- Consider immutability at design time
- Document read-only nature in API

## 5. Multithreading: Sleep vs Wait

### Thread.sleep()
**Purpose**: Pauses the current thread execution for a specified time
**Characteristics**:
- **Static method**: Called on Thread class
- **No lock release**: Thread holds any locks it has
- **Interruption**: Can be interrupted, throws InterruptedException
- **Usage**: Time-based delays, polling scenarios

**Example**:
```java
public class SleepExample {
    public synchronized void sleepMethod() {
        try {
            System.out.println("Thread sleeping for 2 seconds");
            Thread.sleep(2000); // Sleeps for 2 seconds
            System.out.println("Thread woke up");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
```

### Object.wait()
**Purpose**: Makes current thread wait until another thread notifies it
**Characteristics**:
- **Instance method**: Called on object
- **Lock release**: Releases the object's monitor
- **Synchronization**: Must be called from synchronized context
- **Notification**: Requires notify() or notifyAll() to wake up

**Example**:
```java
public class WaitExample {
    private final Object lock = new Object();
    private boolean condition = false;
    
    public void waitMethod() {
        synchronized (lock) {
            while (!condition) {
                try {
                    System.out.println("Thread waiting for condition");
                    lock.wait(); // Releases lock and waits
                    System.out.println("Thread notified");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
    
    public void notifyMethod() {
        synchronized (lock) {
            condition = true;
            lock.notify(); // Wakes up waiting thread
        }
    }
}
```

### Key Differences

| Aspect | Thread.sleep() | Object.wait() |
|--------|----------------|---------------|
| **Method Type** | Static | Instance |
| **Lock Release** | No | Yes |
| **Synchronization** | Not required | Required |
| **Wake Up** | Time-based | Notification-based |
| **Usage** | Delays | Inter-thread communication |

**When to Use**:
- **sleep()**: Simple delays, polling, timeouts
- **wait()**: Producer-consumer patterns, condition synchronization

**Best Practices**:
```java
// Always handle InterruptedException
try {
    Thread.sleep(1000);
} catch (InterruptedException e) {
    Thread.currentThread().interrupt();
    // Handle interruption appropriately
}

// Always use wait() in a loop
synchronized (lock) {
    while (!condition) {
        lock.wait();
    }
}
```

## 6. Creating Two Threads to Print Odd and Even Numbers from ArrayList

### Solution 1: Using Synchronized Block
```java
public class OddEvenPrinter {
    private List<Integer> numbers;
    private int currentIndex = 0;
    private final Object lock = new Object();
    
    public OddEvenPrinter(List<Integer> numbers) {
        this.numbers = numbers;
    }
    
    public void printOddEven() {
        Thread oddThread = new Thread(() -> printOdd());
        Thread evenThread = new Thread(() -> printEven());
        
        oddThread.start();
        evenThread.start();
    }
    
    private void printOdd() {
        while (currentIndex < numbers.size()) {
            synchronized (lock) {
                while (currentIndex < numbers.size() && numbers.get(currentIndex) % 2 == 0) {
                    try {
                        lock.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                
                if (currentIndex < numbers.size()) {
                    System.out.println("Odd Thread: " + numbers.get(currentIndex));
                    currentIndex++;
                    lock.notify();
                }
            }
        }
    }
    
    private void printEven() {
        while (currentIndex < numbers.size()) {
            synchronized (lock) {
                while (currentIndex < numbers.size() && numbers.get(currentIndex) % 2 != 0) {
                    try {
                        lock.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                
                if (currentIndex < numbers.size()) {
                    System.out.println("Even Thread: " + numbers.get(currentIndex));
                    currentIndex++;
                    lock.notify();
                }
            }
        }
    }
}
```

### Solution 2: Using ReentrantLock and Condition
```java
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class OddEvenPrinterWithLock {
    private List<Integer> numbers;
    private int currentIndex = 0;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition oddCondition = lock.newCondition();
    private final Condition evenCondition = lock.newCondition();
    
    public OddEvenPrinterWithLock(List<Integer> numbers) {
        this.numbers = numbers;
    }
    
    public void printOddEven() {
        Thread oddThread = new Thread(() -> printOdd());
        Thread evenThread = new Thread(() -> printEven());
        
        oddThread.start();
        evenThread.start();
    }
    
    private void printOdd() {
        while (currentIndex < numbers.size()) {
            lock.lock();
            try {
                while (currentIndex < numbers.size() && numbers.get(currentIndex) % 2 == 0) {
                    oddCondition.await();
                }
                
                if (currentIndex < numbers.size()) {
                    System.out.println("Odd Thread: " + numbers.get(currentIndex));
                    currentIndex++;
                    evenCondition.signal();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                lock.unlock();
            }
        }
    }
    
    private void printEven() {
        while (currentIndex < numbers.size()) {
            lock.lock();
            try {
                while (currentIndex < numbers.size() && numbers.get(currentIndex) % 2 != 0) {
                    evenCondition.await();
                }
                
                if (currentIndex < numbers.size()) {
                    System.out.println("Even Thread: " + numbers.get(currentIndex));
                    currentIndex++;
                    oddCondition.signal();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } finally {
                lock.unlock();
            }
        }
    }
}
```

## 7. Producer-Consumer Pattern in Multithreading

### Classic Producer-Consumer Implementation
```java
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ProducerConsumer {
    private final BlockingQueue<Integer> queue;
    private final int capacity;
    
    public ProducerConsumer(int capacity) {
        this.capacity = capacity;
        this.queue = new LinkedBlockingQueue<>(capacity);
    }
    
    public void start() {
        Thread producer = new Thread(() -> produce());
        Thread consumer = new Thread(() -> consume());
        
        producer.start();
        consumer.start();
    }
    
    private void produce() {
        try {
            for (int i = 0; i < 10; i++) {
                System.out.println("Produced: " + i);
                queue.put(i); // Blocks if queue is full
                Thread.sleep(100);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    private void consume() {
        try {
            while (true) {
                Integer item = queue.take(); // Blocks if queue is empty
                System.out.println("Consumed: " + item);
                Thread.sleep(200);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
```

### Using Synchronized Block Implementation
```java
public class ProducerConsumerSynchronized {
    private final List<Integer> buffer;
    private final int capacity;
    private final Object lock = new Object();
    
    public ProducerConsumerSynchronized(int capacity) {
        this.capacity = capacity;
        this.buffer = new ArrayList<>();
    }
    
    public void produce() throws InterruptedException {
        synchronized (lock) {
            while (buffer.size() == capacity) {
                lock.wait(); // Wait if buffer is full
            }
            
            int item = (int) (Math.random() * 100);
            buffer.add(item);
            System.out.println("Produced: " + item);
            lock.notify(); // Notify consumer
        }
    }
    
    public void consume() throws InterruptedException {
        synchronized (lock) {
            while (buffer.isEmpty()) {
                lock.wait(); // Wait if buffer is empty
            }
            
            int item = buffer.remove(0);
            System.out.println("Consumed: " + item);
            lock.notify(); // Notify producer
        }
    }
}
```

## 8. Synchronization: Block Level vs Method Level

### Method Level Synchronization
```java
public class MethodLevelSync {
    private int counter = 0;
    
    // Synchronized method - locks entire object
    public synchronized void increment() {
        counter++;
        System.out.println("Counter: " + counter);
    }
    
    // Another synchronized method - same lock
    public synchronized void decrement() {
        counter--;
        System.out.println("Counter: " + counter);
    }
    
    // Non-synchronized method - no lock required
    public void printCounter() {
        System.out.println("Current counter: " + counter);
    }
}
```

### Block Level Synchronization
```java
public class BlockLevelSync {
    private int counter = 0;
    private final Object lock1 = new Object();
    private final Object lock2 = new Object();
    
    // Synchronized block with specific lock
    public void increment() {
        synchronized (lock1) {
            counter++;
            System.out.println("Counter: " + counter);
        }
    }
    
    // Different synchronized block with different lock
    public void processData() {
        synchronized (lock2) {
            // Process data independently
            System.out.println("Processing data...");
        }
    }
    
    // Synchronized block with this object
    public void decrement() {
        synchronized (this) {
            counter--;
            System.out.println("Counter: " + counter);
        }
    }
}
```

### Key Differences

| Aspect | Method Level | Block Level |
|--------|--------------|-------------|
| **Lock Scope** | Entire object | Specific object/block |
| **Performance** | Coarse-grained | Fine-grained |
| **Flexibility** | Less flexible | More flexible |
| **Deadlock Risk** | Higher | Lower |
| **Use Cases** | Simple scenarios | Complex scenarios |

### Best Practices
```java
public class BestPractices {
    private final Object lock1 = new Object();
    private final Object lock2 = new Object();
    
    // Good: Use specific locks for different resources
    public void updateResource1() {
        synchronized (lock1) {
            // Update resource 1
        }
    }
    
    public void updateResource2() {
        synchronized (lock2) {
            // Update resource 2
        }
    }
    
    // Avoid: Synchronizing on String literals
    // synchronized ("lock") { } // BAD
    
    // Good: Use private final objects
    private final String lockString = "lock";
    public void goodSync() {
        synchronized (lockString) {
            // Safe synchronization
        }
    }
}
```

## 9. Volatile vs Atomic Variables

### Volatile Keyword
**Purpose**: Ensures visibility of changes across threads
**Characteristics**:
- **Visibility**: Changes are immediately visible to other threads
- **No Atomicity**: Doesn't guarantee atomic operations
- **No Ordering**: Doesn't provide ordering guarantees
- **Performance**: Minimal performance impact

**Example**:
```java
public class VolatileExample {
    private volatile boolean flag = false;
    
    public void setFlag() {
        flag = true; // Immediately visible to other threads
    }
    
    public boolean getFlag() {
        return flag; // Always sees the latest value
    }
    
    // BAD: Volatile doesn't make compound operations atomic
    private volatile int counter = 0;
    
    public void increment() {
        counter++; // NOT atomic - race condition possible
    }
}
```

### Atomic Variables
**Purpose**: Provides atomic operations for thread-safe programming
**Characteristics**:
- **Atomicity**: Operations are indivisible
- **Visibility**: Changes are immediately visible
- **Performance**: Better than synchronized blocks
- **CAS Operations**: Uses Compare-And-Swap for efficiency

**Example**:
```java
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class AtomicExample {
    private AtomicInteger counter = new AtomicInteger(0);
    private AtomicBoolean flag = new AtomicBoolean(false);
    private AtomicReference<String> message = new AtomicReference<>("Hello");
    
    public void increment() {
        counter.incrementAndGet(); // Atomic operation
    }
    
    public void setFlag() {
        flag.set(true); // Atomic operation
    }
    
    public void updateMessage() {
        message.updateAndGet(current -> current + " World");
    }
    
    // CAS operation example
    public boolean compareAndSet(int expected, int newValue) {
        return counter.compareAndSet(expected, newValue);
    }
}
```

### Performance Comparison
```java
public class PerformanceComparison {
    private volatile int volatileCounter = 0;
    private AtomicInteger atomicCounter = new AtomicInteger(0);
    private int synchronizedCounter = 0;
    private final Object lock = new Object();
    
    // Volatile - fast but not atomic
    public void incrementVolatile() {
        volatileCounter++; // Race condition
    }
    
    // Atomic - fast and thread-safe
    public void incrementAtomic() {
        atomicCounter.incrementAndGet();
    }
    
    // Synchronized - slower but guaranteed
    public void incrementSynchronized() {
        synchronized (lock) {
            synchronizedCounter++;
        }
    }
}
```

### When to Use

**Use Volatile When**:
- Single variable updates
- Visibility is the only concern
- Simple boolean flags
- Performance is critical

**Use Atomic Variables When**:
- Compound operations needed
- Counter operations
- Reference updates
- CAS operations required

**Use Synchronized When**:
- Complex operations
- Multiple variables
- Custom synchronization logic
- Legacy code compatibility

## 10. Spring Scopes and Custom Scope Implementation

### Built-in Spring Scopes

**1. Singleton (Default)**
```java
@Component
@Scope("singleton") // Default, can be omitted
public class SingletonService {
    private int counter = 0;
    
    public void increment() {
        counter++;
    }
    
    public int getCounter() {
        return counter;
    }
}
```

**2. Prototype**
```java
@Component
@Scope("prototype")
public class PrototypeService {
    private int counter = 0;
    
    public void increment() {
        counter++;
    }
    
    public int getCounter() {
        return counter;
    }
}
```

**3. Request Scope**
```java
@Component
@Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class RequestScopedService {
    private String requestId = UUID.randomUUID().toString();
    
    public String getRequestId() {
        return requestId;
    }
}
```

**4. Session Scope**
```java
@Component
@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
public class SessionScopedService {
    private String sessionId = UUID.randomUUID().toString();
    
    public String getSessionId() {
        return sessionId;
    }
}
```

### Custom Scope Implementation
```java
public class CustomScope implements Scope {
    private final Map<String, Object> cache = new ConcurrentHashMap<>();
    private final Object lock = new Object();
    
    @Override
    public Object get(String name, ObjectFactory<?> objectFactory) {
        Object object = cache.get(name);
        if (object == null) {
            synchronized (lock) {
                object = cache.get(name);
                if (object == null) {
                    object = objectFactory.getObject();
                    cache.put(name, object);
                }
            }
        }
        return object;
    }
    
    @Override
    public Object remove(String name) {
        return cache.remove(name);
    }
    
    @Override
    public void registerDestructionCallback(String name, Runnable callback) {
        // Register cleanup callback
    }
    
    @Override
    public Object resolveContextualObject(String key) {
        return null;
    }
    
    @Override
    public String getConversationId() {
        return "custom-scope";
    }
}
```

### Registering Custom Scope
```java
@Configuration
public class CustomScopeConfig {
    
    @Bean
    public CustomScopeBeanFactoryPostProcessor customScopeBeanFactoryPostProcessor() {
        return new CustomScopeBeanFactoryPostProcessor();
    }
    
    public static class CustomScopeBeanFactoryPostProcessor implements BeanFactoryPostProcessor {
        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
            beanFactory.registerScope("custom", new CustomScope());
        }
    }
}
```

### Using Custom Scope
```java
@Component
@Scope("custom")
public class CustomScopedService {
    private final String id = UUID.randomUUID().toString();
    
    public String getId() {
        return id;
    }
}
```

## 11. Spring Security

### Basic Configuration
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasRole("USER")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login?logout")
            )
            .csrf(csrf -> csrf.disable());
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### Custom Authentication
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        return org.springframework.security.core.userdetails.User
            .withUsername(user.getUsername())
            .password(user.getPassword())
            .roles(user.getRoles().toArray(new String[0]))
            .build();
    }
}
```

### JWT Authentication
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtTokenProvider tokenProvider;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwt = getJwtFromRequest(request);
            
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                String userId = tokenProvider.getUserIdFromJWT(jwt);
                UserDetails userDetails = customUserDetailsService.loadUserById(userId);
                
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

### Method-Level Security
```java
@Service
public class SecureService {
    
    @PreAuthorize("hasRole('ADMIN')")
    public void adminOnlyMethod() {
        // Only admins can access
    }
    
    @PreAuthorize("hasRole('USER') and #user.id == authentication.principal.id")
    public void userSpecificMethod(User user) {
        // Users can only access their own data
    }
    
    @PostAuthorize("returnObject.owner == authentication.principal.username")
    public Document getDocument(Long id) {
        // Return document only if user owns it
        return documentRepository.findById(id);
    }
}
```

## 12. One-to-Many Relationship

### JPA/Hibernate Implementation
```java
@Entity
@Table(name = "departments")
public class Department {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    @OneToMany(mappedBy = "department", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Employee> employees = new ArrayList<>();
    
    // Getters and setters
    public void addEmployee(Employee employee) {
        employees.add(employee);
        employee.setDepartment(this);
    }
    
    public void removeEmployee(Employee employee) {
        employees.remove(employee);
        employee.setDepartment(null);
    }
}

@Entity
@Table(name = "employees")
public class Employee {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String name;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "department_id")
    private Department department;
    
    // Getters and setters
}
```

### Repository Layer
```java
@Repository
public interface DepartmentRepository extends JpaRepository<Department, Long> {
    @Query("SELECT d FROM Department d LEFT JOIN FETCH d.employees")
    List<Department> findAllWithEmployees();
    
    @Query("SELECT d FROM Department d LEFT JOIN FETCH d.employees WHERE d.id = :id")
    Optional<Department> findByIdWithEmployees(@Param("id") Long id);
}

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {
    List<Employee> findByDepartmentId(Long departmentId);
}
```

### Service Layer
```java
@Service
@Transactional
public class DepartmentService {
    
    @Autowired
    private DepartmentRepository departmentRepository;
    
    @Autowired
    private EmployeeRepository employeeRepository;
    
    public Department createDepartmentWithEmployees(Department department) {
        return departmentRepository.save(department);
    }
    
    public void addEmployeeToDepartment(Long departmentId, Employee employee) {
        Department department = departmentRepository.findById(departmentId)
            .orElseThrow(() -> new EntityNotFoundException("Department not found"));
        
        department.addEmployee(employee);
        departmentRepository.save(department);
    }
    
    public List<Employee> getEmployeesByDepartment(Long departmentId) {
        return employeeRepository.findByDepartmentId(departmentId);
    }
}
```

### DTOs for API
```java
public class DepartmentDTO {
    private Long id;
    private String name;
    private List<EmployeeDTO> employees;
    
    // Getters and setters
}

public class EmployeeDTO {
    private Long id;
    private String name;
    private Long departmentId;
    
    // Getters and setters
}
```

## 13. Distributed Transaction Management

### Two-Phase Commit (2PC)
```java
@Service
public class DistributedTransactionService {
    
    @Autowired
    private OrderService orderService;
    
    @Autowired
    private InventoryService inventoryService;
    
    @Autowired
    private PaymentService paymentService;
    
    @Transactional
    public void processOrder(Order order) {
        try {
            // Phase 1: Prepare
            boolean orderPrepared = orderService.prepareOrder(order);
            boolean inventoryPrepared = inventoryService.prepareInventory(order.getItems());
            boolean paymentPrepared = paymentService.preparePayment(order.getPayment());
            
            if (orderPrepared && inventoryPrepared && paymentPrepared) {
                // Phase 2: Commit
                orderService.commitOrder(order.getId());
                inventoryService.commitInventory(order.getItems());
                paymentService.commitPayment(order.getPayment().getId());
            } else {
                // Rollback
                orderService.rollbackOrder(order.getId());
                inventoryService.rollbackInventory(order.getItems());
                paymentService.rollbackPayment(order.getPayment().getId());
            }
        } catch (Exception e) {
            // Rollback on exception
            rollbackAll(order);
            throw new RuntimeException("Transaction failed", e);
        }
    }
    
    private void rollbackAll(Order order) {
        try {
            orderService.rollbackOrder(order.getId());
            inventoryService.rollbackInventory(order.getItems());
            paymentService.rollbackPayment(order.getPayment().getId());
        } catch (Exception e) {
            // Log rollback failures
        }
    }
}
```

### Saga Pattern Implementation
```java
@Service
public class OrderSagaService {
    
    @Autowired
    private OrderService orderService;
    
    @Autowired
    private InventoryService inventoryService;
    
    @Autowired
    private PaymentService paymentService;
    
    public void processOrderSaga(Order order) {
        try {
            // Step 1: Create Order
            Order createdOrder = orderService.createOrder(order);
            
            // Step 2: Reserve Inventory
            inventoryService.reserveInventory(order.getItems());
            
            // Step 3: Process Payment
            paymentService.processPayment(order.getPayment());
            
            // Step 4: Confirm Order
            orderService.confirmOrder(createdOrder.getId());
            
        } catch (Exception e) {
            // Compensating actions
            compensateOrder(order);
        }
    }
    
    private void compensateOrder(Order order) {
        try {
            // Reverse payment
            paymentService.reversePayment(order.getPayment().getId());
            
            // Release inventory
            inventoryService.releaseInventory(order.getItems());
            
            // Cancel order
            orderService.cancelOrder(order.getId());
            
        } catch (Exception e) {
            // Log compensation failures
        }
    }
}
```

### Event-Driven Saga
```java
@Component
public class OrderSagaEventHandler {
    
    @EventListener
    public void handleOrderCreated(OrderCreatedEvent event) {
        try {
            // Reserve inventory
            inventoryService.reserveInventory(event.getOrder().getItems());
        } catch (Exception e) {
            // Publish compensation event
            eventPublisher.publishEvent(new OrderCancelledEvent(event.getOrder()));
        }
    }
    
    @EventListener
    public void handleInventoryReserved(InventoryReservedEvent event) {
        try {
            // Process payment
            paymentService.processPayment(event.getOrder().getPayment());
        } catch (Exception e) {
            // Publish compensation events
            eventPublisher.publishEvent(new InventoryReleasedEvent(event.getOrder()));
            eventPublisher.publishEvent(new OrderCancelledEvent(event.getOrder()));
        }
    }
    
    @EventListener
    public void handlePaymentProcessed(PaymentProcessedEvent event) {
        // Confirm order
        orderService.confirmOrder(event.getOrder().getId());
    }
}
```

## 14. Microservices Problem Tracing

### Distributed Tracing with Spring Cloud Sleuth
```java
@SpringBootApplication
@EnableDiscoveryClient
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}
```

### Tracing Configuration
```yaml
# application.yml
spring:
  application:
    name: order-service
  sleuth:
    sampler:
      probability: 1.0
    web:
      client:
        enabled: true
    messaging:
      enabled: true
```

### Service Implementation with Tracing
```java
@Service
public class OrderService {
    
    private final Tracer tracer;
    private final RestTemplate restTemplate;
    
    public OrderService(Tracer tracer, RestTemplate restTemplate) {
        this.tracer = tracer;
        this.restTemplate = restTemplate;
    }
    
    public Order processOrder(OrderRequest request) {
        Span span = tracer.nextSpan().name("process-order");
        
        try (SpanInScope ws = tracer.withSpanInScope(span.start())) {
            // Create order
            Order order = createOrder(request);
            
            // Call inventory service
            InventoryResponse inventoryResponse = callInventoryService(order);
            
            // Call payment service
            PaymentResponse paymentResponse = callPaymentService(order);
            
            // Update order status
            order.setStatus("CONFIRMED");
            return orderRepository.save(order);
            
        } finally {
            span.finish();
        }
    }
    
    private InventoryResponse callInventoryService(Order order) {
        Span span = tracer.nextSpan().name("call-inventory-service");
        
        try (SpanInScope ws = tracer.withSpanInScope(span.start())) {
            String url = "http://inventory-service/api/inventory/reserve";
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-B3-TraceId", tracer.currentSpan().context().traceIdString());
            headers.set("X-B3-SpanId", tracer.currentSpan().context().spanIdString());
            
            HttpEntity<InventoryRequest> entity = new HttpEntity<>(order.getItems(), headers);
            return restTemplate.postForObject(url, entity, InventoryResponse.class);
            
        } finally {
            span.finish();
        }
    }
}
```

### Circuit Breaker Pattern
```java
@Service
public class ResilientOrderService {
    
    @HystrixCommand(fallbackMethod = "fallbackInventoryService")
    public InventoryResponse callInventoryService(Order order) {
        return restTemplate.postForObject(
            "http://inventory-service/api/inventory/reserve",
            order.getItems(),
            InventoryResponse.class
        );
    }
    
    public InventoryResponse fallbackInventoryService(Order order, Throwable t) {
        // Fallback logic
        return new InventoryResponse("FALLBACK", "Inventory service unavailable");
    }
    
    @HystrixCommand(fallbackMethod = "fallbackPaymentService")
    public PaymentResponse callPaymentService(Order order) {
        return restTemplate.postForObject(
            "http://payment-service/api/payment/process",
            order.getPayment(),
            PaymentResponse.class
        );
    }
    
    public PaymentResponse fallbackPaymentService(Order order, Throwable t) {
        // Fallback logic
        return new PaymentResponse("FALLBACK", "Payment service unavailable");
    }
}
```

### API Gateway with Tracing
```java
@Configuration
public class GatewayConfig {
    
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("order-service", r -> r
                .path("/api/orders/**")
                .filters(f -> f
                    .addRequestHeader("X-Response-Time", System.currentTimeMillis() + "")
                    .circuitBreaker(config -> config
                        .setName("order-service-circuit")
                        .setFallbackUri("forward:/fallback/order-service")
                    )
                )
                .uri("lb://order-service")
            )
            .route("inventory-service", r -> r
                .path("/api/inventory/**")
                .filters(f -> f
                    .addRequestHeader("X-Response-Time", System.currentTimeMillis() + "")
                )
                .uri("lb://inventory-service")
            )
            .build();
    }
}
```

## 15. Session Factory for Multiple DataSources

### Multiple DataSource Configuration
```java
@Configuration
public class DataSourceConfig {
    
    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource.primary")
    public DataSource primaryDataSource() {
        return DataSourceBuilder.create().build();
    }
    
    @Bean
    @ConfigurationProperties("spring.datasource.secondary")
    public DataSource secondaryDataSource() {
        return DataSourceBuilder.create().build();
    }
    
    @Bean
    @Primary
    public LocalContainerEntityManagerFactoryBean primaryEntityManagerFactory(
            EntityManagerFactoryBuilder builder,
            @Qualifier("primaryDataSource") DataSource dataSource) {
        
        return builder
            .dataSource(dataSource)
            .packages("com.example.primary.entity")
            .persistenceUnit("primary")
            .build();
    }
    
    @Bean
    public LocalContainerEntityManagerFactoryBean secondaryEntityManagerFactory(
            EntityManagerFactoryBuilder builder,
            @Qualifier("secondaryDataSource") DataSource dataSource) {
        
        return builder
            .dataSource(dataSource)
            .packages("com.example.secondary.entity")
            .persistenceUnit("secondary")
            .build();
    }
    
    @Bean
    @Primary
    public PlatformTransactionManager primaryTransactionManager(
            @Qualifier("primaryEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }
    
    @Bean
    public PlatformTransactionManager secondaryTransactionManager(
            @Qualifier("secondaryEntityManagerFactory") EntityManagerFactory entityManagerFactory) {
        return new JpaTransactionManager(entityManagerFactory);
    }
}
```

### Hibernate Session Factory Configuration
```java
@Configuration
public class HibernateConfig {
    
    @Bean
    @Primary
    public SessionFactory primarySessionFactory(
            @Qualifier("primaryDataSource") DataSource dataSource) {
        
        LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();
        sessionFactory.setDataSource(dataSource);
        sessionFactory.setPackagesToScan("com.example.primary.entity");
        
        Properties hibernateProperties = new Properties();
        hibernateProperties.setProperty("hibernate.dialect", "org.hibernate.dialect.MySQL8Dialect");
        hibernateProperties.setProperty("hibernate.show_sql", "true");
        hibernateProperties.setProperty("hibernate.hbm2ddl.auto", "update");
        
        sessionFactory.setHibernateProperties(hibernateProperties);
        sessionFactory.afterPropertiesSet();
        
        return sessionFactory.getObject();
    }
    
    @Bean
    public SessionFactory secondarySessionFactory(
            @Qualifier("secondaryDataSource") DataSource dataSource) {
        
        LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();
        sessionFactory.setDataSource(dataSource);
        sessionFactory.setPackagesToScan("com.example.secondary.entity");
        
        Properties hibernateProperties = new Properties();
        hibernateProperties.setProperty("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        hibernateProperties.setProperty("hibernate.show_sql", "true");
        hibernateProperties.setProperty("hibernate.hbm2ddl.auto", "update");
        
        sessionFactory.setHibernateProperties(hibernateProperties);
        sessionFactory.afterPropertiesSet();
        
        return sessionFactory.getObject();
    }
}
```

### Service Layer with Multiple DataSources
```java
@Service
public class MultiDataSourceService {
    
    @Autowired
    @Qualifier("primarySessionFactory")
    private SessionFactory primarySessionFactory;
    
    @Autowired
    @Qualifier("secondarySessionFactory")
    private SessionFactory secondarySessionFactory;
    
    @Transactional("primaryTransactionManager")
    public void saveToPrimary(PrimaryEntity entity) {
        Session session = primarySessionFactory.getCurrentSession();
        session.save(entity);
    }
    
    @Transactional("secondaryTransactionManager")
    public void saveToSecondary(SecondaryEntity entity) {
        Session session = secondarySessionFactory.getCurrentSession();
        session.save(entity);
    }
    
    public List<PrimaryEntity> getFromPrimary() {
        Session session = primarySessionFactory.getCurrentSession();
        return session.createQuery("from PrimaryEntity", PrimaryEntity.class).list();
    }
    
    public List<SecondaryEntity> getFromSecondary() {
        Session session = secondarySessionFactory.getCurrentSession();
        return session.createQuery("from SecondaryEntity", SecondaryEntity.class).list();
    }
}
```

## 16. Builder Pattern Usage

### Advanced Builder Pattern
```java
public class DatabaseConfig {
    private final String host;
    private final int port;
    private final String database;
    private final String username;
    private final String password;
    private final int maxConnections;
    private final int timeout;
    private final boolean ssl;
    
    private DatabaseConfig(Builder builder) {
        this.host = builder.host;
        this.port = builder.port;
        this.database = builder.database;
        this.username = builder.username;
        this.password = builder.password;
        this.maxConnections = builder.maxConnections;
        this.timeout = builder.timeout;
        this.ssl = builder.ssl;
    }
    
    public static class Builder {
        private String host = "localhost";
        private int port = 5432;
        private String database;
        private String username;
        private String password;
        private int maxConnections = 10;
        private int timeout = 30;
        private boolean ssl = false;
        
        public Builder(String database) {
            this.database = database;
        }
        
        public Builder host(String host) {
            this.host = host;
            return this;
        }
        
        public Builder port(int port) {
            this.port = port;
            return this;
        }
        
        public Builder credentials(String username, String password) {
            this.username = username;
            this.password = password;
            return this;
        }
        
        public Builder maxConnections(int maxConnections) {
            this.maxConnections = maxConnections;
            return this;
        }
        
        public Builder timeout(int timeout) {
            this.timeout = timeout;
            return this;
        }
        
        public Builder enableSsl() {
            this.ssl = true;
            return this;
        }
        
        public DatabaseConfig build() {
            if (database == null || username == null || password == null) {
                throw new IllegalStateException("Database, username, and password are required");
            }
            return new DatabaseConfig(this);
        }
    }
    
    // Getters
    public String getHost() { return host; }
    public int getPort() { return port; }
    public String getDatabase() { return database; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public int getMaxConnections() { return maxConnections; }
    public int getTimeout() { return timeout; }
    public boolean isSsl() { return ssl; }
}

// Usage
DatabaseConfig config = new DatabaseConfig.Builder("myapp")
    .host("db.example.com")
    .port(5432)
    .credentials("user", "pass")
    .maxConnections(20)
    .timeout(60)
    .enableSsl()
    .build();
```

### Generic Builder Pattern
```java
public abstract class AbstractBuilder<T> {
    protected abstract T build();
    
    public T construct() {
        validate();
        return build();
    }
    
    protected void validate() {
        // Default validation - can be overridden
    }
}

public class ProductBuilder extends AbstractBuilder<Product> {
    private String name;
    private String description;
    private BigDecimal price;
    private List<String> categories = new ArrayList<>();
    
    public ProductBuilder name(String name) {
        this.name = name;
        return this;
    }
    
    public ProductBuilder description(String description) {
        this.description = description;
        return this;
    }
    
    public ProductBuilder price(BigDecimal price) {
        this.price = price;
        return this;
    }
    
    public ProductBuilder category(String category) {
        this.categories.add(category);
        return this;
    }
    
    @Override
    protected Product build() {
        return new Product(name, description, price, categories);
    }
    
    @Override
    protected void validate() {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalStateException("Product name is required");
        }
        if (price == null || price.compareTo(BigDecimal.ZERO) < 0) {
            throw new IllegalStateException("Valid price is required");
        }
    }
}
```

## 17. Proxy Design Pattern

### Static Proxy
```java
public interface UserService {
    void createUser(String username);
    void deleteUser(String username);
}

public class UserServiceImpl implements UserService {
    @Override
    public void createUser(String username) {
        System.out.println("Creating user: " + username);
    }
    
    @Override
    public void deleteUser(String username) {
        System.out.println("Deleting user: " + username);
    }
}

public class UserServiceProxy implements UserService {
    private UserService userService;
    private Logger logger = LoggerFactory.getLogger(UserServiceProxy.class);
    
    public UserServiceProxy(UserService userService) {
        this.userService = userService;
    }
    
    @Override
    public void createUser(String username) {
        logger.info("Before creating user: " + username);
        try {
            userService.createUser(username);
            logger.info("Successfully created user: " + username);
        } catch (Exception e) {
            logger.error("Failed to create user: " + username, e);
            throw e;
        }
    }
    
    @Override
    public void deleteUser(String username) {
        logger.info("Before deleting user: " + username);
        try {
            userService.deleteUser(username);
            logger.info("Successfully deleted user: " + username);
        } catch (Exception e) {
            logger.error("Failed to delete user: " + username, e);
            throw e;
        }
    }
}
```

### Dynamic Proxy (JDK)
```java
public class LoggingInvocationHandler implements InvocationHandler {
    private final Object target;
    private final Logger logger = LoggerFactory.getLogger(LoggingInvocationHandler.class);
    
    public LoggingInvocationHandler(Object target) {
        this.target = target;
    }
    
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        logger.info("Before method: " + method.getName());
        long startTime = System.currentTimeMillis();
        
        try {
            Object result = method.invoke(target, args);
            long endTime = System.currentTimeMillis();
            logger.info("Method " + method.getName() + " took " + (endTime - startTime) + "ms");
            return result;
        } catch (Exception e) {
            logger.error("Exception in method: " + method.getName(), e);
            throw e;
        }
    }
}

// Usage
UserService userService = new UserServiceImpl();
UserService proxy = (UserService) Proxy.newProxyInstance(
    UserService.class.getClassLoader(),
    new Class<?>[] { UserService.class },
    new LoggingInvocationHandler(userService)
);
```

### CGLIB Proxy
```java
public class CglibProxyFactory {
    
    public static <T> T createProxy(T target, Class<T> clazz) {
        Enhancer enhancer = new Enhancer();
        enhancer.setSuperclass(clazz);
        enhancer.setCallback(new MethodInterceptor() {
            @Override
            public Object intercept(Object obj, Method method, Object[] args, 
                                  MethodProxy proxy) throws Throwable {
                System.out.println("Before method: " + method.getName());
                Object result = proxy.invokeSuper(obj, args);
                System.out.println("After method: " + method.getName());
                return result;
            }
        });
        
        return (T) enhancer.create();
    }
}

// Usage
UserService userService = new UserServiceImpl();
UserService proxy = CglibProxyFactory.createProxy(userService, UserServiceImpl.class);
```

### Spring AOP Proxy
```java
@Aspect
@Component
public class LoggingAspect {
    
    private static final Logger logger = LoggerFactory.getLogger(LoggingAspect.class);
    
    @Around("@annotation(Loggable)")
    public Object logMethod(ProceedingJoinPoint joinPoint) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        logger.info("Before method: " + methodName);
        
        long startTime = System.currentTimeMillis();
        try {
            Object result = joinPoint.proceed();
            long endTime = System.currentTimeMillis();
            logger.info("Method " + methodName + " took " + (endTime - startTime) + "ms");
            return result;
        } catch (Exception e) {
            logger.error("Exception in method: " + methodName, e);
            throw e;
        }
    }
}

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Loggable {
}

@Service
public class UserService {
    
    @Loggable
    public void createUser(String username) {
        System.out.println("Creating user: " + username);
    }
}
```

## 18. Factory Design Pattern

### Simple Factory
```java
public interface Animal {
    void makeSound();
}

public class Dog implements Animal {
    @Override
    public void makeSound() {
        System.out.println("Woof!");
    }
}

public class Cat implements Animal {
    @Override
    public void makeSound() {
        System.out.println("Meow!");
    }
}

public class AnimalFactory {
    public static Animal createAnimal(String type) {
        switch (type.toLowerCase()) {
            case "dog":
                return new Dog();
            case "cat":
                return new Cat();
            default:
                throw new IllegalArgumentException("Unknown animal type: " + type);
        }
    }
}

// Usage
Animal dog = AnimalFactory.createAnimal("dog");
Animal cat = AnimalFactory.createAnimal("cat");
```

### Factory Method Pattern
```java
public abstract class AnimalCreator {
    abstract Animal createAnimal();
    
    public void makeAnimalSound() {
        Animal animal = createAnimal();
        animal.makeSound();
    }
}

public class DogCreator extends AnimalCreator {
    @Override
    Animal createAnimal() {
        return new Dog();
    }
}

public class CatCreator extends AnimalCreator {
    @Override
    Animal createAnimal() {
        return new Cat();
    }
}

// Usage
AnimalCreator dogCreator = new DogCreator();
AnimalCreator catCreator = new CatCreator();
dogCreator.makeAnimalSound();
catCreator.makeAnimalSound();
```

### Abstract Factory Pattern
```java
public interface AnimalFactory {
    Animal createAnimal();
    Food createFood();
}

public class DogFactory implements AnimalFactory {
    @Override
    public Animal createAnimal() {
        return new Dog();
    }
    
    @Override
    public Food createFood() {
        return new DogFood();
    }
}

public class CatFactory implements AnimalFactory {
    @Override
    public Animal createAnimal() {
        return new Cat();
    }
    
    @Override
    public Food createFood() {
        return new CatFood();
    }
}

// Usage
AnimalFactory dogFactory = new DogFactory();
Animal dog = dogFactory.createAnimal();
Food dogFood = dogFactory.createFood();
```

### Parameterized Factory
```java
public class ConfigurableFactory<T> {
    private final Map<String, Supplier<T>> creators = new HashMap<>();
    
    public void register(String type, Supplier<T> creator) {
        creators.put(type, creator);
    }
    
    public T create(String type) {
        Supplier<T> creator = creators.get(type);
        if (creator == null) {
            throw new IllegalArgumentException("Unknown type: " + type);
        }
        return creator.get();
    }
}

// Usage
ConfigurableFactory<Animal> factory = new ConfigurableFactory<>();
factory.register("dog", Dog::new);
factory.register("cat", Cat::new);

Animal dog = factory.create("dog");
Animal cat = factory.create("cat");
```

### Spring Factory Bean
```java
@Component
public class AnimalFactoryBean implements FactoryBean<Animal> {
    
    private String animalType;
    
    public void setAnimalType(String animalType) {
        this.animalType = animalType;
    }
    
    @Override
    public Animal getObject() throws Exception {
        switch (animalType) {
            case "dog":
                return new Dog();
            case "cat":
                return new Cat();
            default:
                throw new IllegalArgumentException("Unknown animal type: " + animalType);
        }
    }
    
    @Override
    public Class<?> getObjectType() {
        return Animal.class;
    }
    
    @Override
    public boolean isSingleton() {
        return false;
    }
}
```

This comprehensive guide covers all the Java interview questions from a senior architect perspective, providing detailed explanations, code examples, and best practices for each topic.

