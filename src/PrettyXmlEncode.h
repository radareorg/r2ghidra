
// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PRETTY_XML_ENCODE_H
#define PRETTY_XML_ENCODE_H

#include <marshal.hh>

class PrettyXmlEncode: public XmlEncode
{
	private:
		int depth = 0;
		void indent();

	public:
		PrettyXmlEncode(std::ostream &s) : XmlEncode(s) {}
		void openElement(const ElementId &elemId) override;
		void closeElement(const ElementId &elemId) override;
};

#endif
