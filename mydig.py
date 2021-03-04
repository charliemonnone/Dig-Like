import os, socket, sys, time, timeit
import dns.query, dns.message, dns.rdatatype, dns.rdataclass
from datetime import date

# ---------- Root Servers ----------
a_root = ["a.root-servers.net", "198.41.0.4"  , 	"2001:503:ba3e::2:30" 	"Verisign, Inc."]
b_root = ["b.root-servers.net", "199.9.14.201", 	"2001:500:200::b" 		"University of Southern California"]
c_root = ["c.root-servers.net", "192.33.4.12" ,		"2001:500:2::c" 		"Cogent Communications"]
d_root = ["d.root-servers.net", "199.7.91.13" ,   	"2001:500:2d::d" 		"University of Maryland"]
e_root = ["e.root-servers.net", "192.203.230.10",	"2001:500:a8::e" 		"NASA (Ames Research Center)"]
f_root = ["f.root-servers.net", "192.5.5.241", 		"2001:500:2f::f" 		"Internet Systems Consortium, Inc."]
g_root = ["g.root-servers.net", "192.112.36.4", 	"2001:500:12::d0d" 		"US Department of Defense (NIC)"]
h_root = ["h.root-servers.net", "198.97.190.53", 	"2001:500:1::53" 		"US Army (Research Lab)"]
i_root = ["i.root-servers.net", "192.36.148.17", 	"2001:7fe::53" 			"Netnod"]
j_root = ["j.root-servers.net", "192.58.128.30", 	"2001:503:c27::2:30" 	"Verisign, Inc."]
k_root = ["k.root-servers.net", "193.0.14.129", 	"2001:7fd::1" 			"RIPE NCC"]
l_root = ["l.root-servers.net", "199.7.83.42", 		"2001:500:9f::42" 		"ICANN"]
m_root = ["m.root-servers.net", "202.12.27.33", 	"2001:dc3::35" 			"WIDE Project"]


# ---------- Constants ----------
A_RECORD = int(dns.rdatatype.A)
CNAME_RECORD = int(dns.rdatatype.CNAME)
NS_RECORD = int(dns.rdatatype.NS)
RESOLVE_CNAME = True
PRINT_TO_FILE = False
first_question = ""

		
def formatted_resp(answer, question, elapsed):
	output = """QUESTION SECTION:\n{}\n\nANSWER SECTION:\n{}\n\nQuery time: {:.1f} msec\nWHEN: {} {} {}""".format(
		question, answer, elapsed * 1000, date.today(), time.strftime('%H:%M:%S'), time.tzname[0])
	return output

def formatted_resp_no_answer(resp, elapsed):
	output = """QUESTION SECTION:\n{}\n\nANSWER SECTION:\n{}\n\nQuery time: {:.1f} msec\nWHEN: {} {} {}""".format(
		resp.question[0], resp.answer, elapsed * 1000, date.today(), time.strftime('%H:%M:%S'), time.tzname[0])
	return output

def print_to_output_file(output, domain_name):
	f = open('mydig_output.txt', 'w')
	f.write("Mydig input: {}\n\n".format(domain_name))
	f.write(output)
	f.close()
	return


def generate_query(domain_name):
	query = dns.message.make_query(qname = domain_name, rdtype = dns.rdatatype.A)
	return query

def resolve_request(domain_name, print_resp, query_ip, time_start = 0, initial = False):
	global first_question
	question = generate_query(domain_name)
	where = query_ip	# ipv4 of verisign root server
	timeout = 10	
	try:
		if(time_start == 0):
			time_start = time.process_time()	# begin timing query, alternative: time.time() 
		(resp, tcp) = dns.query.udp_with_fallback(q = question, where = where, timeout = timeout, ignore_trailing = True)
		
		if(initial):							# if this is the initial request, log input
			first_question = resp.question[0]

		while(resp.additional != [] and resp.answer == []):		# keep making requests until an answer or no additional
			additional = resp.additional
			for entry in additional:
				if entry.rdtype == A_RECORD:	# use the first available ipv4 address from additional section
						where = str(entry[0])	# as the next where parameter 
						break
			(resp, tcp) = dns.query.udp_with_fallback(q = question, where = where, timeout = timeout, ignore_trailing = True)
		
		if(resp.answer):
			for a in resp.answer:
				if(a.rdtype == CNAME_RECORD and RESOLVE_CNAME):	
					resolve_request(str(a[0]), True, query_ip, time.process_time() - time_start)
					break
				elif(a.rdtype == A_RECORD and print_resp):
					time_end = time.process_time()			# end timer
					elapsed = time_end - time_start			# calculate msec since first query
					output = formatted_resp(a, first_question, elapsed)	# print A record
					print(output)
					break
		elif(resp.authority[0].rdtype == NS_RECORD):	# resolve NS record if no answer
				ns_resp = resolve_request(str(resp.authority[0][0]), False, a_root[1])
				new_ip = ""
				for entry in ns_resp.answer:
					if entry.rdtype == A_RECORD:	# use the first available ipv4 address from additional section
						new_ip = str(entry[0])		# as the next where parameter 
						break
				resolve_request(domain_name, True, new_ip, time.process_time() - time_start)

		if(PRINT_TO_FILE):
			print_to_output_file(output, domain_name) 
	
# TODO: Convert mydig_output to pdf]
	except BlockingIOError:
		print("A non-blocking socket operation could not be completed immediately")
	except dns.exception.Timeout:
		print("The DNS operation timed out.")

	return resp

	#  matplotlib for part b

def main():
	resolve_request(str(sys.argv[1]), True, a_root[1], 0,True)



if __name__ == "__main__":
	print("----------")
	main()
	print("----------")
