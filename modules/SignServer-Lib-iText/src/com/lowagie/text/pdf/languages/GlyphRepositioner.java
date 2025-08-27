package com.lowagie.text.pdf.languages;

import java.util.List;

import com.lowagie.text.pdf.Glyph;

/**
 *  
 * @author <a href="mailto:paawak@gmail.com">Palash Ray</a>
 */
public interface GlyphRepositioner {
	
	void repositionGlyphs(List<Glyph> glyphList);
	
}
