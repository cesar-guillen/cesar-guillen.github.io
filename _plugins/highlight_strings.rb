# _plugins/highlight_in_code.rb
Jekyll::Hooks.register :documents, :post_render do |doc|
  next unless doc.output_ext == ".html"
  
  # Add span tags around ==text== in code blocks
  doc.output = doc.output.gsub(/<code[^>]*>(.*?)<\/code>/m) do |code_block|
    code_block.gsub(/==([^=]+)==/) do |match|
      "<span class=\"code-highlight\">#{$1}</span>"
    end
  end
end