import pinger
from ping3 import ping
import random



def get_stats(count, addr):
	total = 0 
	minval = float('inf')
	maxval = -1
	for i in range(0,count):
		pinged = ping(addr,unit='ms', size = 56)
		if pinged == False:
			return [-1, -1, -1]
		total += pinged
		if pinged < minval:
			minval = pinged
		if pinged > maxval:
			maxval = pinged
	avg = total/count
	return [minval, maxval, avg]


def do_compare(msg, cnt, addr):
	str_compare = pinger.print_ping_stats(msg, cnt, addr)
	compare_arr = str_compare.split(",")
	if compare_arr[2] == "N/A":
		pass_test = False
	else:
		min_student = float(compare_arr[0])
		max_student = float(compare_arr[1])
		avg_student = float(compare_arr[2]) 

		real_test = get_stats(cnt, addr)
		min_real = float(real_test[0])
		max_real = float(real_test[1])
		avg_real = float(real_test[2])
		if (avg_real == -1):
			return False 
		within_range = max(3, 0.1*avg_real)
		print("Student Average: ", str(avg_student), "Actual Average : ", str(avg_real))
		pass_test = (avg_real - within_range <= avg_student <= avg_real + within_range)
		return pass_test



def test_1(): 

	msg = ""
	str_compare = pinger.print_ping_stats("", 10, "127.0.0.1")
	compare_arr = str_compare.split(",")
	if compare_arr[2] == "N/A":
		pass_test = False 
	else: 
		min_student = float(compare_arr[0])
		max_student = float(compare_arr[1])
		avg_student = float(compare_arr[2]) 

		real_test = get_stats(10, "127.0.0.1")
		min_real = float(real_test[0])
		max_real = float(real_test[1])
		avg_real = float(real_test[2])
		within_range = max(3, 0.1*avg_real)

		pass_test = (avg_real - within_range <= avg_student <= avg_real + within_range)

	assert pass_test == True 

def test_2(): 
	msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	cnt = 13 
	addr = "www.usc.edu"
	pass_test = do_compare(msg,cnt, addr)

	assert pass_test == True 

def test_3():
	msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	cnt = 13 
	addr = "www.google.com"
	pass_test = do_compare(msg,cnt, addr)

	assert pass_test == True 

def test_4():
	msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
	cnt = 8 
	addr = "www.oxford.ac.uk"
	pass_test = do_compare(msg,cnt, addr)

	assert pass_test == True 

def test_5(): 
	msg = "time for a random test of slow websites"
	cnt = 10 
	addresses = ["www.126.com", "www.sina.com.cn", "cooks.org.kp",
				"mail.ru", "www.mfa.gov.tm"]
	random_choice = random.randint(0, 4)
	addr = addresses[random_choice]

	pass_test = do_compare(msg,cnt, addr)

	assert pass_test == True 