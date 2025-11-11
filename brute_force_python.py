"""
Brute Force Protection System
نظام الحماية من هجمات القوة الغاشمة

A lightweight, in-memory rate limiter to protect authentication endpoints
from brute force attacks.

محدد معدل خفيف الوزن في الذاكرة لحماية نقاط المصادقة من هجمات القوة الغاشمة.

Author: Your Name
GitHub: https://github.com/YOUR_USERNAME/brute-force-protection
License: MIT
Version: 1.0.0
"""

from collections import defaultdict
import time
from typing import Dict, List, Optional


class LoginAttemptMonitor:
    """
    Monitor and rate-limit login attempts to prevent brute force attacks.
    مراقبة وتحديد معدل محاولات تسجيل الدخول لمنع هجمات القوة الغاشمة.
    
    This class tracks failed login attempts by identifier (IP address, username, etc.)
    and enforces a lockout period after too many failed attempts within a time window.
    
    تتبع هذه الفئة محاولات تسجيل الدخول الفاشلة حسب المعرف (عنوان IP، اسم المستخدم، إلخ)
    وتفرض فترة حظر بعد محاولات فاشلة كثيرة جدًا خلال نافذة زمنية.
    
    Attributes:
        max_attempts (int): Maximum number of failed attempts before lockout
                           الحد الأقصى لعدد المحاولات الفاشلة قبل الحظر
        lockout_time (int): Duration of lockout in seconds
                           مدة الحظر بالثواني
        attempts (dict): Dictionary storing attempt timestamps per identifier
                        قاموس يخزن الطوابع الزمنية للمحاولات لكل معرف
    
    Example:
        >>> monitor = LoginAttemptMonitor(max_attempts=5, lockout_time=300)
        >>> if monitor.is_allowed('192.168.1.100'):
        ...     # Process login attempt
        ...     if login_failed:
        ...         monitor.record_attempt('192.168.1.100')
        >>> status = monitor.get_status('192.168.1.100')
        >>> print(f"Remaining attempts: {status['remaining_attempts']}")
    """
    
    def __init__(self, max_attempts: int = 5, lockout_time: int = 300):
        """
        Initialize the login attempt monitor.
        تهيئة مراقب محاولات تسجيل الدخول.
        
        Args:
            max_attempts (int): Maximum failed attempts before lockout (default: 5)
                               الحد الأقصى للمحاولات الفاشلة قبل الحظر (افتراضي: 5)
            lockout_time (int): Lockout duration in seconds (default: 300)
                               مدة الحظر بالثواني (افتراضي: 300)
        
        Raises:
            ValueError: If max_attempts or lockout_time are not positive integers
        """
        if max_attempts <= 0:
            raise ValueError("max_attempts must be a positive integer")
        if lockout_time <= 0:
            raise ValueError("lockout_time must be a positive integer")
        
        self.attempts: Dict[str, List[float]] = defaultdict(list)
        self.max_attempts = max_attempts
        self.lockout_time = lockout_time
    
    def is_allowed(self, identifier: str) -> bool:
        """
        Check if a login attempt is allowed for the given identifier.
        التحقق مما إذا كانت محاولة تسجيل الدخول مسموحة للمعرف المحدد.
        
        This method checks if the identifier has exceeded the maximum number of
        failed attempts within the lockout time window. Old attempts outside
        the time window are automatically removed.
        
        تتحقق هذه الطريقة مما إذا كان المعرف قد تجاوز الحد الأقصى لعدد المحاولات
        الفاشلة ضمن النافذة الزمنية للحظر. تتم إزالة المحاولات القديمة خارج
        النافذة الزمنية تلقائيًا.
        
        Args:
            identifier (str): Unique identifier (IP address, username, etc.)
                            معرف فريد (عنوان IP، اسم المستخدم، إلخ)
        
        Returns:
            bool: True if attempt is allowed, False if locked out
                  True إذا كانت المحاولة مسموحة، False إذا كانت محظورة
        
        Example:
            >>> monitor = LoginAttemptMonitor(max_attempts=3, lockout_time=60)
            >>> monitor.is_allowed('user123')
            True
            >>> for _ in range(3):
            ...     monitor.record_attempt('user123')
            >>> monitor.is_allowed('user123')
            False
        """
        current_time = time.time()
        
        # Remove old attempts outside the time window
        # إزالة المحاولات القديمة خارج النافذة الزمنية
        self.attempts[identifier] = [
            timestamp for timestamp in self.attempts[identifier]
            if current_time - timestamp < self.lockout_time
        ]
        
        # Check if maximum attempts exceeded
        # التحقق مما إذا تم تجاوز الحد الأقصى للمحاولات
        return len(self.attempts[identifier]) < self.max_attempts
    
    def record_attempt(self, identifier: str) -> None:
        """
        Record a failed login attempt for the given identifier.
        تسجيل محاولة تسجيل دخول فاشلة للمعرف المحدد.
        
        This method adds a timestamp for the current failed attempt. It should
        only be called after a failed login attempt.
        
        تضيف هذه الطريقة طابعًا زمنيًا للمحاولة الفاشلة الحالية. يجب استدعاؤها
        فقط بعد محاولة تسجيل دخول فاشلة.
        
        Args:
            identifier (str): Unique identifier to track
                            معرف فريد للتتبع
        
        Example:
            >>> monitor = LoginAttemptMonitor()
            >>> if not validate_password(username, password):
            ...     monitor.record_attempt(ip_address)
        """
        self.attempts[identifier].append(time.time())
    
    def get_status(self, identifier: str) -> Dict[str, any]:
        """
        Get the current status for an identifier.
        الحصول على الحالة الحالية لمعرف.
        
        Returns detailed information about the current state including whether
        the identifier is locked, number of attempts, and time until unlock.
        
        يُرجع معلومات مفصلة عن الحالة الحالية بما في ذلك ما إذا كان المعرف
        محظورًا وعدد المحاولات والوقت حتى إلغاء الحظر.
        
        Args:
            identifier (str): Identifier to check
                            المعرف للتحقق منه
        
        Returns:
            dict: Status information with the following keys:
                  معلومات الحالة بالمفاتيح التالية:
                  
                  When locked (عند الحظر):
                  - locked (bool): True if locked
                  - attempts (int): Number of failed attempts
                  - unlock_in_seconds (int): Seconds until unlock
                  
                  When not locked (عند عدم الحظر):
                  - locked (bool): False
                  - attempts (int): Number of failed attempts
                  - remaining_attempts (int): Attempts remaining before lockout
        
        Example:
            >>> monitor = LoginAttemptMonitor(max_attempts=5, lockout_time=300)
            >>> monitor.record_attempt('user123')
            >>> status = monitor.get_status('user123')
            >>> print(status)
            {'locked': False, 'attempts': 1, 'remaining_attempts': 4}
        """
        current_time = time.time()
        
        # Filter recent attempts within the time window
        # تصفية المحاولات الأخيرة ضمن النافذة الزمنية
        recent_attempts = [
            timestamp for timestamp in self.attempts[identifier]
            if current_time - timestamp < self.lockout_time
        ]
        
        # Check if identifier is locked
        # التحقق مما إذا كان المعرف محظورًا
        if len(recent_attempts) >= self.max_attempts:
            oldest_attempt = min(recent_attempts)
            time_until_unlock = self.lockout_time - (current_time - oldest_attempt)
            
            return {
                "locked": True,
                "attempts": len(recent_attempts),
                "unlock_in_seconds": int(time_until_unlock)
            }
        
        # Not locked - return remaining attempts
        # غير محظور - إرجاع المحاولات المتبقية
        return {
            "locked": False,
            "attempts": len(recent_attempts),
            "remaining_attempts": self.max_attempts - len(recent_attempts)
        }
    
    def reset(self, identifier: str) -> None:
        """
        Reset all attempts for a specific identifier.
        إعادة تعيين جميع المحاولات لمعرف محدد.
        
        This can be used to manually unlock an identifier or clear attempts
        after a successful login.
        
        يمكن استخدام هذا لإلغاء قفل معرف يدويًا أو مسح المحاولات بعد تسجيل
        دخول ناجح.
        
        Args:
            identifier (str): Identifier to reset
                            المعرف لإعادة التعيين
        
        Example:
            >>> monitor = LoginAttemptMonitor()
            >>> monitor.reset('user123')  # Clear all attempts for user123
        """
        if identifier in self.attempts:
            del self.attempts[identifier]
    
    def get_all_locked_identifiers(self) -> List[str]:
        """
        Get a list of all currently locked identifiers.
        الحصول على قائمة بجميع المعرفات المحظورة حاليًا.
        
        Returns:
            list: List of locked identifier strings
                  قائمة بسلاسل المعرفات المحظورة
        
        Example:
            >>> monitor = LoginAttemptMonitor()
            >>> locked = monitor.get_all_locked_identifiers()
            >>> print(f"Locked users: {len(locked)}")
        """
        current_time = time.time()
        locked = []
        
        for identifier, timestamps in self.attempts.items():
            recent = [t for t in timestamps if current_time - t < self.lockout_time]
            if len(recent) >= self.max_attempts:
                locked.append(identifier)
        
        return locked
    
    def cleanup_old_entries(self, age_threshold: Optional[int] = None) -> int:
        """
        Remove identifiers with no recent attempts to free up memory.
        إزالة المعرفات التي ليس لها محاولات حديثة لتحرير الذاكرة.
        
        Args:
            age_threshold (int, optional): Remove entries older than this (seconds)
                                          إزالة المدخلات الأقدم من هذا (ثواني)
                                          Defaults to lockout_time
        
        Returns:
            int: Number of entries removed
                 عدد المدخلات المحذوفة
        
        Example:
            >>> monitor = LoginAttemptMonitor()
            >>> cleaned = monitor.cleanup_old_entries()
            >>> print(f"Cleaned {cleaned} old entries")
        """
        if age_threshold is None:
            age_threshold = self.lockout_time
        
        current_time = time.time()
        identifiers_to_remove = []
        
        for identifier, timestamps in self.attempts.items():
            # Remove if all attempts are older than threshold
            # الإزالة إذا كانت جميع المحاولات أقدم من العتبة
            if all(current_time - t > age_threshold for t in timestamps):
                identifiers_to_remove.append(identifier)
        
        for identifier in identifiers_to_remove:
            del self.attempts[identifier]
        
        return len(identifiers_to_remove)


class MultiFactorBruteForceProtection:
    """
    Track both IP addresses and usernames for enhanced protection.
    تتبع كل من عناوين IP وأسماء المستخدمين لحماية محسنة.
    
    This class combines IP-based and username-based rate limiting to provide
    more comprehensive protection against brute force attacks.
    
    تجمع هذه الفئة بين تحديد المعدل على أساس IP واسم المستخدم لتوفير حماية
    أكثر شمولاً ضد هجمات القوة الغاشمة.
    
    Example:
        >>> protection = MultiFactorBruteForceProtection()
        >>> if protection.is_allowed('192.168.1.1', 'admin'):
        ...     # Process login
        ...     if login_failed:
        ...         protection.record_failed_attempt('192.168.1.1', 'admin')
    """
    
    def __init__(self,
                 ip_max_attempts: int = 20,
                 ip_lockout_time: int = 300,
                 user_max_attempts: int = 5,
                 user_lockout_time: int = 600):
        """
        Initialize multi-factor brute force protection.
        تهيئة الحماية متعددة العوامل من القوة الغاشمة.
        
        Args:
            ip_max_attempts (int): Max attempts per IP (default: 20)
            ip_lockout_time (int): IP lockout duration in seconds (default: 300)
            user_max_attempts (int): Max attempts per username (default: 5)
            user_lockout_time (int): Username lockout duration in seconds (default: 600)
        """
        # More lenient for IPs (multiple users may share IP)
        # أكثر تساهلاً لعناوين IP (قد يشارك عدة مستخدمين نفس IP)
        self.ip_monitor = LoginAttemptMonitor(
            max_attempts=ip_max_attempts,
            lockout_time=ip_lockout_time
        )
        
        # Stricter for usernames (targeted attacks)
        # أكثر صرامة لأسماء المستخدمين (هجمات مستهدفة)
        self.user_monitor = LoginAttemptMonitor(
            max_attempts=user_max_attempts,
            lockout_time=user_lockout_time
        )
    
    def is_allowed(self, ip_address: str, username: str) -> bool:
        """
        Check if login attempt is allowed for both IP and username.
        التحقق مما إذا كانت محاولة تسجيل الدخول مسموحة لكل من IP واسم المستخدم.
        
        Args:
            ip_address (str): IP address of the client
            username (str): Username being attempted
        
        Returns:
            bool: True if both IP and username are allowed
        """
        ip_allowed = self.ip_monitor.is_allowed(ip_address)
        user_allowed = self.user_monitor.is_allowed(username)
        
        return ip_allowed and user_allowed
    
    def record_failed_attempt(self, ip_address: str, username: str) -> None:
        """
        Record failed attempt for both IP and username.
        تسجيل محاولة فاشلة لكل من IP واسم المستخدم.
        
        Args:
            ip_address (str): IP address of the client
            username (str): Username that failed
        """
        self.ip_monitor.record_attempt(ip_address)
        self.user_monitor.record_attempt(username)
    
    def get_detailed_status(self, ip_address: str, username: str) -> Dict[str, Dict]:
        """
        Get status for both IP and username.
        الحصول على الحالة لكل من IP واسم المستخدم.
        
        Returns:
            dict: Status for both identifiers
        """
        return {
            "ip_status": self.ip_monitor.get_status(ip_address),
            "user_status": self.user_monitor.get_status(username)
        }
    
    def reset_user(self, username: str) -> None:
        """Reset attempts for a username."""
        self.user_monitor.reset(username)
    
    def reset_ip(self, ip_address: str) -> None:
        """Reset attempts for an IP address."""
        self.ip_monitor.reset(ip_address)


def demo():
    """
    Demonstration of the brute force protection system.
    عرض توضيحي لنظام الحماية من القوة الغاشمة.
    """
    print("=" * 60)
    print("Brute Force Protection Demo")
    print("عرض توضيحي للحماية من القوة الغاشمة")
    print("=" * 60)
    print()
    
    # Initialize monitor with 3 attempts and 10 second lockout
    # تهيئة المراقب مع 3 محاولات وحظر لمدة 10 ثوانٍ
    monitor = LoginAttemptMonitor(max_attempts=3, lockout_time=10)
    test_ip = "192.168.1.100"
    
    print(f"Testing IP: {test_ip}")
    print(f"اختبار IP: {test_ip}")
    print(f"Max attempts: 3 | Lockout time: 10 seconds")
    print(f"الحد الأقصى للمحاولات: 3 | وقت الحظر: 10 ثوانٍ")
    print()
    
    # Simulate login attempts
    # محاكاة محاولات تسجيل الدخول
    for i in range(5):
        print(f"--- Attempt {i+1} | المحاولة {i+1} ---")
        
        if monitor.is_allowed(test_ip):
            print(f"✓ Login attempt ALLOWED | محاولة تسجيل الدخول مسموحة")
            monitor.record_attempt(test_ip)
            
            status = monitor.get_status(test_ip)
            print(f"  Attempts made: {status['attempts']}")
            print(f"  المحاولات المنفذة: {status['attempts']}")
            
            if not status['locked']:
                print(f"  Remaining attempts: {status['remaining_attempts']}")
                print(f"  المحاولات المتبقية: {status['remaining_attempts']}")
        else:
            status = monitor.get_status(test_ip)
            print(f"✗ Login attempt BLOCKED | محاولة تسجيل الدخول محظورة")
            print(f"  Account is locked for {status['unlock_in_seconds']} seconds")
            print(f"  الحساب محظور لمدة {status['unlock_in_seconds']} ثانية")
        
        print()
    
    # Wait for unlock
    # انتظر حتى يتم إلغاء الحظر
    print("Waiting 11 seconds for lockout to expire...")
    print("انتظار 11 ثانية حتى ينتهي الحظر...")
    time.sleep(11)
    print()
    
    print("--- After lockout period | بعد فترة الحظر ---")
    if monitor.is_allowed(test_ip):
        print("✓ Account is now UNLOCKED | الحساب الآن غير محظور")
        status = monitor.get_status(test_ip)
        print(f"  Remaining attempts: {status['remaining_attempts']}")
        print(f"  المحاولات المتبقية: {status['remaining_attempts']}")
    
    print()
    print("=" * 60)
    print("Demo completed successfully!")
    print("اكتمل العرض التوضيحي بنجاح!")
    print("=" * 60)


if __name__ == "__main__":
    # Run the demo when script is executed directly
    # تشغيل العرض التوضيحي عند تنفيذ البرنامج مباشرة
    demo()
