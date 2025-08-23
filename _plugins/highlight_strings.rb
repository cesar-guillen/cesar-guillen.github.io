# _plugins/highlight_in_code.rb
require 'nokogiri'

Jekyll::Hooks.register :documents, :post_render do |doc|
  next unless doc.output_ext == ".html"
  
  # Parse the HTML document
  parsed_doc = Nokogiri::HTML.parse(doc.output)
  
  # Find all code blocks
  parsed_doc.search('code').each do |code_block|
    # Replace ==text== with highlighted spans
    code_block.inner_html = code_block.inner_html.gsub(/==([^=]+)==/) do |match|
      "<span class=\"code-highlight\">#{$1}</span>"
    end
  end
  
  # Update the document output
  doc.output = parsed_doc.to_html
end