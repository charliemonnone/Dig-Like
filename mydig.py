import os, socket, sys, time, timeit
import dns.query, dns.message, dns.rdatatype, dns.rdataclass
from datetime import date
from multiprocessing import Process, Value, Array
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
REFUSED_RCODE = int(dns.rcode.REFUSED)
RESOLVE_CNAME = True
PRINT_TO_FILE = False
first_question = ""
initialQ = True
cname = []

		
def formatted_resp(answer, cname, question, elapsed):
	global first_question
	cname_print = ""
	if(cname):
		length = len(cname)
		for c in cname:
			length -= 1
			cname_print += str(cname[0])
			if(length > 0):
				cname_print += '\n'

	output = """QUESTION SECTION:\n{}\n\nANSWER SECTION:\n{}\n{}\n\nQuery time: {:.1f} msec\nWHEN: {} {} {}""".format(
		first_question, cname_print, answer, elapsed * 1000, date.today(), time.strftime('%H:%M:%S'), time.tzname[0])
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

def resolve_request(domain_name, print_resp, query_ip = a_root[1], time_start = 0, cname = []):
	global first_question
	global initialQ
	question = generate_query(domain_name)
	where = query_ip	# ipv4 of verisign root server
	timeout = 5	
	try:
		if(time_start == 0):
			time_start = time.time()	# begin timing query, alternative: time.time() 
		(resp, tcp) = dns.query.udp_with_fallback(q = question, where = where, timeout = timeout, ignore_trailing = True)
		if(initialQ):							# if this is the initial request, log input
			initialQ = False
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
				if(a.rdtype == CNAME_RECORD):	
					cname.append(a)
					resolve_request(str(a[0]), print_resp, query_ip, time_start, cname)
					break
				elif(a.rdtype == A_RECORD and print_resp):
					time_end = time.time()			# end timer
					elapsed = time_end - time_start			# calculate msec since first query
					output = formatted_resp(a, cname, first_question, elapsed)	# print A record
					print(output)
					break
		elif(resp.authority and resp.authority[0].rdtype == NS_RECORD):	# resolve NS record if no answer
				ns_resp = resolve_request(str(resp.authority[0][0]), False, a_root[1], cname)
				new_ip = ""
				for entry in ns_resp.answer:
					if entry.rdtype == A_RECORD:	# use the first available ipv4 address from additional section
						new_ip = str(entry[0])		# as the next where parameter 
						break
				resolve_request(domain_name, print_resp, new_ip, time_start, cname)
		elif(resp.rcode() == REFUSED_RCODE):
			resolve_request(domain_name, print_resp, a_root[1], time_start, cname)

		if(PRINT_TO_FILE):
			print_to_output_file(output, domain_name) 
	
	except BlockingIOError:
		print("A non-blocking socket operation could not be completed immediately")
		return
	except dns.exception.Timeout:
		resolve_request(domain_name, print_resp, a_root[1], time_start, cname)
		return
	
	return resp

	#  matplotlib for part b

def main():
	global cname
	resolve_request(str(sys.argv[1]), True, a_root[1], 0, cname)



if __name__ == "__main__":
	print("")
	main()
	print("")
