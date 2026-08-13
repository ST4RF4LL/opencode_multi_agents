import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class RequestSizeAllocation {
  @GetMapping("/buffer")
  byte[] buffer(@RequestParam int size) {
    return new byte[size];
  }
}
