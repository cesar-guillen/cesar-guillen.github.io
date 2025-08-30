# _plugins/highlight_in_code.rb
require 'nokogiri'

Jekyll::Hooks.register [:documents, :pages], :post_render do |doc|
  next unless doc.output_ext == ".html"

  # Parse full HTML (tolerant parser, keeps DOCTYPE and headers intact)
  parsed_doc = Nokogiri::HTML::Document.parse(doc.output) do |config|
    config.recover 
  end

  parsed_doc.css('code').each do |code_block|
    html = code_block.inner_html.dup

    # Case 1: Rouge tokenized the markers (== as <span class="o">==</span>)
    html.gsub!(%r{
      <span[^>]*class="[^"]*\bo\b[^"]*"[^>]*>\s*==\s*</span>
      (.*?)
      <span[^>]*class="[^"]*\bo\b[^"]*"[^>]*>\s*==\s*</span>
    }mx) do
      inner = Regexp.last_match(1)
      %Q{<span class="code-highlight">#{inner}</span>}
    end

    # Case 2: Plain ==text== (no Rouge spans)
    html.gsub!(/==([^=]+)==/) do
      %Q{<span class="code-highlight">#{$1}</span>}
    end

    code_block.inner_html = html
  end

  # Write back full HTML
  doc.output = parsed_doc.to_html
end
