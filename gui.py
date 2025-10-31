from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import List

from .engine import evaluate_packet
from .models import Action, Direction, Packet, Rule, parse_ip_spec, parse_port_spec
from .parser import parse_rules


class FirewallSimulatorGUI(ttk.Frame):
	def __init__(self, master: tk.Tk):
		super().__init__(master)
		self.master.title("Firewall Rule Simulator")
		self.pack(fill=tk.BOTH, expand=True)

		self.rules: List[Rule] = []

		self._build_widgets()

	def _build_widgets(self):
		# Rules section
		rules_frame = ttk.LabelFrame(self, text="Rules")
		rules_frame.pack(fill=tk.BOTH, expand=False, padx=8, pady=8)

		btns = ttk.Frame(rules_frame)
		btns.pack(fill=tk.X, padx=4, pady=4)
		self.btn_load = ttk.Button(btns, text="Load Rules", command=self._load_rules)
		self.btn_load.pack(side=tk.LEFT)
		self.btn_clear = ttk.Button(btns, text="Clear", command=self._clear_rules)
		self.btn_clear.pack(side=tk.LEFT, padx=(6, 0))

		self.tree = ttk.Treeview(rules_frame, columns=("action","dir","proto","src","dst","sport","dport"), show="headings", height=6)
		for col in ("action","dir","proto","src","dst","sport","dport"):
			self.tree.heading(col, text=col)
			self.tree.column(col, width=110, anchor=tk.W)
		self.tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

		form = ttk.LabelFrame(self, text="Add / Edit Rule")
		form.pack(fill=tk.X, padx=8, pady=4)
		self.var_action = tk.StringVar(value="ALLOW")
		self.var_dir = tk.StringVar(value="IN")
		self.var_proto = tk.StringVar(value="ANY")
		self.var_src = tk.StringVar()
		self.var_dst = tk.StringVar()
		self.var_sport = tk.StringVar()
		self.var_dport = tk.StringVar()

		row = ttk.Frame(form)
		row.pack(fill=tk.X, padx=4, pady=4)
		for label, widget in (
			("Action", ttk.Combobox(row, textvariable=self.var_action, values=["ALLOW","BLOCK","LOG"], width=8, state="readonly")),
			("Dir", ttk.Combobox(row, textvariable=self.var_dir, values=["IN","OUT"], width=6, state="readonly")),
			("Proto", ttk.Combobox(row, textvariable=self.var_proto, values=["ANY","TCP","UDP","ICMP"], width=8, state="readonly")),
			("Src", ttk.Entry(row, textvariable=self.var_src, width=18)),
			("Dst", ttk.Entry(row, textvariable=self.var_dst, width=18)),
			("Sport", ttk.Entry(row, textvariable=self.var_sport, width=8)),
			("Dport", ttk.Entry(row, textvariable=self.var_dport, width=8)),
		):
			lbl = ttk.Label(row, text=label)
			lbl.pack(side=tk.LEFT, padx=(0,4))
			widget.pack(side=tk.LEFT, padx=(0,10))

		row_btns = ttk.Frame(form)
		row_btns.pack(fill=tk.X, padx=4, pady=(0,6))
		self.btn_add = ttk.Button(row_btns, text="Add Rule", command=self._add_rule)
		self.btn_add.pack(side=tk.LEFT)
		self.btn_delete = ttk.Button(row_btns, text="Delete Selected", command=self._delete_selected_rule)
		self.btn_delete.pack(side=tk.LEFT, padx=(6,0))

		# Packet test section
		test = ttk.LabelFrame(self, text="Test Packet")
		test.pack(fill=tk.X, padx=8, pady=8)
		self.t_dir = tk.StringVar(value="IN")
		self.t_proto = tk.StringVar(value="TCP")
		self.t_src = tk.StringVar()
		self.t_dst = tk.StringVar()
		self.t_sport = tk.StringVar()
		self.t_dport = tk.StringVar()

		rowt = ttk.Frame(test)
		rowt.pack(fill=tk.X, padx=4, pady=4)
		for label, widget in (
			("Dir", ttk.Combobox(rowt, textvariable=self.t_dir, values=["IN","OUT"], width=6, state="readonly")),
			("Proto", ttk.Combobox(rowt, textvariable=self.t_proto, values=["TCP","UDP","ICMP"], width=8, state="readonly")),
			("Src", ttk.Entry(rowt, textvariable=self.t_src, width=18)),
			("Dst", ttk.Entry(rowt, textvariable=self.t_dst, width=18)),
			("Sport", ttk.Entry(rowt, textvariable=self.t_sport, width=8)),
			("Dport", ttk.Entry(rowt, textvariable=self.t_dport, width=8)),
		):
			lbl = ttk.Label(rowt, text=label)
			lbl.pack(side=tk.LEFT, padx=(0,4))
			widget.pack(side=tk.LEFT, padx=(0,10))

		self.btn_eval = ttk.Button(test, text="Evaluate", command=self._evaluate_packet)
		self.btn_eval.pack(side=tk.LEFT, padx=8, pady=(0,6))
		self.lbl_result = ttk.Label(test, text="Decision: -")
		self.lbl_result.pack(side=tk.LEFT, padx=8)

	def _refresh_tree(self):
		for row in self.tree.get_children():
			self.tree.delete(row)
		for idx, r in enumerate(self.rules):
			self.tree.insert("", tk.END, iid=str(idx), values=(
				r.action,
				r.direction or "any",
				r.protocol or "any",
				str(r.source_ip_spec or "any"),
				str(r.destination_ip_spec or "any"),
				str(r.source_port_spec or "any"),
				str(r.destination_port_spec or "any"),
			))

	def _load_rules(self):
		path = filedialog.askopenfilename(title="Open Rules File", filetypes=[("Text", "*.txt"), ("All", "*.*")])
		if not path:
			return
		try:
			text = Path(path).read_text(encoding="utf-8")
			self.rules = parse_rules(text)
			self._refresh_tree()
		except Exception as exc:
			messagebox.showerror("Error", f"Failed to load rules:\n{exc}")

	def _clear_rules(self):
		self.rules = []
		self._refresh_tree()

	def _add_rule(self):
		try:
			action = Action(self.var_action.get())
			dir_val = Direction(self.var_dir.get()) if self.var_dir.get() else None
			proto = (self.var_proto.get() or "").upper()
			if proto == "ANY":
				proto = None
			src = self.var_src.get().strip() or None
			dst = self.var_dst.get().strip() or None
			sport = self.var_sport.get().strip() or None
			dport = self.var_dport.get().strip() or None
			rule = Rule(
				action=action,
				direction=dir_val,
				protocol=proto,
				source_ip_spec=parse_ip_spec(src) if src else None,
				destination_ip_spec=parse_ip_spec(dst) if dst else None,
				source_port_spec=parse_port_spec(sport) if sport else None,
				destination_port_spec=parse_port_spec(dport) if dport else None,
			)
			self.rules.append(rule)
			self._refresh_tree()
		except Exception as exc:
			messagebox.showerror("Invalid Rule", str(exc))

	def _delete_selected_rule(self):
		selection = self.tree.selection()
		if not selection:
			return
		idx = int(selection[0])
		if 0 <= idx < len(self.rules):
			self.rules.pop(idx)
			self._refresh_tree()

	def _evaluate_packet(self):
		try:
			pkt = Packet(
				direction=Direction(self.t_dir.get()),
				protocol=(self.t_proto.get() or None),
				source_ip=self.t_src.get().strip() or None,
				destination_ip=self.t_dst.get().strip() or None,
				source_port=int(self.t_sport.get()) if self.t_sport.get().strip() else None,
				destination_port=int(self.t_dport.get()) if self.t_dport.get().strip() else None,
			)
			decision = evaluate_packet(self.rules, pkt)
			self.lbl_result.configure(text=f"Decision: {decision.final_action}{' (default)' if decision.defaulted else ''}")
		except Exception as exc:
			messagebox.showerror("Error", str(exc))


def main():
	root = tk.Tk()
	root.geometry("920x520")
	app = FirewallSimulatorGUI(root)
	root.mainloop()


if __name__ == "__main__":
	main()


